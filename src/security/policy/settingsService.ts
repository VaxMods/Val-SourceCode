import crypto from "node:crypto";
import type { Logger } from "pino";
import { coerceSettingValue, describeValue, getSetting, isWeakening, type SettingDefinition } from "../../config/settings.js";
import type { GuildPolicy } from "../../config/schema.js";
import { validatePolicySemantics } from "../../config/validation.js";
import type { Clock } from "../../core/clock.js";
import { ValidationError, errorMessage } from "../../core/errors.js";
import type { WhitelistScope } from "../../core/types.js";
import type { Repositories } from "../../database/repositories/index.js";
import type { ChannelInfo, DiscordGateway, GuildInfo, RoleInfo } from "../../discord/gateway.js";
import { dangerousBits, namesOf } from "../../discord/permissions.js";
import type { AlertSink } from "../alerts/alertService.js";
import { buildEmbed, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import { hasAccess, type AccessLevel } from "./authorization.js";
import type { PolicyContext, PolicyService } from "./policyService.js";

export interface Actor {
  userId: string;
  access: AccessLevel;
}

export type ChangeRequest =
  | { kind: "setting"; path: string; value: unknown }
  | { kind: "protectedRoles"; roleIds: string[] }
  | { kind: "roleGranters"; roleId: string; userIds: string[]; roleIds: string[] }
  | { kind: "whitelistAdd"; subjectId: string; scope: WhitelistScope; reason: string; hours: number | null }
  | { kind: "whitelistRevoke"; subjectIds: string[]; reason: string };

export interface PlannedChange {
  label: string;
  previous: string;
  next: string;
  weakening: boolean;
  ownerOnly: boolean;
  evidence: Record<string, unknown>;
}

export interface ChangePlan {
  id: string;
  guildId: string;
  requests: ChangeRequest[];
  changes: PlannedChange[];
  weakening: boolean;
  requiredAccess: AccessLevel;
  notes: string[];
}

export type PlanOutcome = { ok: true; plan: ChangePlan } | { ok: false; error: string };

export interface CommitOutcome {
  ok: boolean;
  message: string;
}

const ACCESS_LABEL: Record<AccessLevel, string> = { none: "nobody", auditor: "an auditor", securityAdmin: "a security administrator", owner: "the server owner" };

function listText(ids: readonly string[], format: (id: string) => string): string {
  return ids.length === 0 ? "none" : ids.map(format).join(", ");
}

export class SettingsService {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly repos: Repositories,
    private readonly evidence: EvidenceSink,
    private readonly alerts: AlertSink,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  async plan(guildId: string, actor: Actor, requests: ChangeRequest[]): Promise<PlanOutcome> {
    try {
      this.policies.invalidate(guildId);
      const context = await this.policies.context(guildId);
      const guild = await this.gateway.getGuild(guildId);
      if (!guild) return { ok: false, error: "The server is unavailable right now; try again in a moment." };
      const roles = await this.gateway.listRoles(guildId);
      const channels = await this.gateway.listChannels(guildId);
      const changes: PlannedChange[] = [];
      const settingChanges: Array<{ path: string; value: unknown }> = [];
      for (const request of requests) {
        switch (request.kind) {
          case "setting": {
            const definition = getSetting(request.path);
            const value = coerceSettingValue(definition, request.value);
            const previous = this.policies.currentValue(context, definition.path);
            if (JSON.stringify(previous) === JSON.stringify(value)) continue;
            await this.validateAgainstGuild(definition, value, guild, roles, channels, context);
            settingChanges.push({ path: definition.path, value });
            changes.push({
              label: definition.label,
              previous: describeValue(definition, previous),
              next: describeValue(definition, value),
              weakening: isWeakening(definition, previous, value),
              ownerOnly: definition.ownerOnly,
              evidence: { setting: definition.path, previous, next: value }
            });
            break;
          }
          case "protectedRoles":
            changes.push(...(await this.planProtectedRoles(context, request.roleIds, guild, roles)));
            break;
          case "roleGranters":
            changes.push(...(await this.planGranters(context, request, roles)));
            break;
          case "whitelistAdd":
            changes.push(await this.planWhitelistAdd(context, guild, actor, request));
            break;
          case "whitelistRevoke": {
            const active = context.whitelist.filter((entry) => request.subjectIds.includes(entry.subjectId));
            if (active.length === 0) continue;
            changes.push({
              label: "Whitelist",
              previous: listText([...new Set(active.map((entry) => entry.subjectId))], (id) => `<@${id}>`),
              next: "revoked",
              weakening: false,
              ownerOnly: false,
              evidence: { action: "whitelist.revoke", subjectIds: request.subjectIds, reason: request.reason }
            });
            break;
          }
        }
      }
      const notes: string[] = [];
      if (settingChanges.length > 0) {
        const candidate = await this.policies.candidate(guildId, settingChanges);
        const before = new Set(validatePolicySemantics(context.policy).warnings);
        notes.push(...validatePolicySemantics(candidate.policy).warnings.filter((warning) => !before.has(warning)));
      }
      if (changes.length === 0) return { ok: false, error: "Nothing changed." };
      const weakening = changes.some((change) => change.weakening);
      const ownerOnly = changes.some((change) => change.ownerOnly);
      const requiredAccess: AccessLevel = ownerOnly || (weakening && context.policy.weakeningChangesRequireOwner) ? "owner" : "securityAdmin";
      const plan: ChangePlan = { id: crypto.randomBytes(6).toString("hex"), guildId, requests, changes, weakening, requiredAccess, notes };
      if (!hasAccess(actor.access, requiredAccess)) {
        const reason = ownerOnly
          ? "This setting can only be changed by the server owner."
          : "This change weakens protection, and weakening changes require the server owner (setting: Owner approval for weakening changes).";
        await this.refused(guildId, actor, plan, reason);
        return { ok: false, error: reason };
      }
      return { ok: true, plan };
    } catch (error) {
      if (error instanceof ValidationError) return { ok: false, error: error.message };
      this.logger.error({ err: errorMessage(error), guildId }, "Settings plan failed");
      return { ok: false, error: "The change could not be prepared; check the bot logs." };
    }
  }

  async commit(actor: Actor, plan: ChangePlan): Promise<CommitOutcome> {
    if (!hasAccess(actor.access, plan.requiredAccess)) return { ok: false, message: `This change requires ${ACCESS_LABEL[plan.requiredAccess]}.` };
    const guildId = plan.guildId;
    try {
      const previousAlertChannel = (await this.policies.context(guildId)).policy.alertChannelId;
      const nowIso = new Date(this.clock.now()).toISOString();
      const settingChanges = plan.requests.flatMap((request) =>
        request.kind === "setting" ? [{ path: request.path, value: coerceSettingValue(getSetting(request.path), request.value) }] : []
      );
      if (settingChanges.length > 0) {
        const candidate = await this.policies.candidate(guildId, settingChanges);
        await this.policies.saveOverrides(guildId, candidate.overrides, candidate.revision, actor.userId);
        const approved = settingChanges.find((change) => change.path === "bots.approvedBotIds");
        if (approved && Array.isArray(approved.value)) {
          for (const botId of approved.value) await this.repos.bots.setStatus(guildId, String(botId), "approved", actor.userId, nowIso);
        }
      }
      for (const request of plan.requests) {
        switch (request.kind) {
          case "setting":
            break;
          case "protectedRoles": {
            const existing = await this.repos.protectedRoles.list(guildId);
            const wanted = new Set(request.roleIds);
            for (const record of existing) if (!wanted.has(record.roleId)) await this.repos.protectedRoles.remove(guildId, record.roleId);
            for (const roleId of wanted) {
              if (existing.some((record) => record.roleId === roleId)) continue;
              await this.repos.protectedRoles.upsert({ guildId, roleId, allowedGranterIds: [], allowedGranterRoleIds: [], createdBy: actor.userId, createdAt: nowIso });
            }
            break;
          }
          case "roleGranters": {
            const existing = (await this.repos.protectedRoles.list(guildId)).find((record) => record.roleId === request.roleId);
            await this.repos.protectedRoles.upsert({
              guildId,
              roleId: request.roleId,
              allowedGranterIds: [...new Set(request.userIds)],
              allowedGranterRoleIds: [...new Set(request.roleIds)],
              createdBy: existing?.createdBy ?? actor.userId,
              createdAt: existing?.createdAt ?? nowIso
            });
            break;
          }
          case "whitelistAdd": {
            const subject = await this.gateway.getMember(guildId, request.subjectId);
            if (subject?.isBot) await this.repos.bots.setStatus(guildId, request.subjectId, "approved", actor.userId, nowIso);
            await this.repos.whitelist.add({
              id: crypto.randomUUID(),
              guildId,
              subjectId: request.subjectId,
              subjectType: subject?.isBot ? "bot" : "user",
              scopes: [request.scope],
              reason: request.reason.slice(0, 300),
              createdBy: actor.userId,
              createdAt: nowIso,
              expiresAt: request.hours ? new Date(this.clock.now() + request.hours * 3600000).toISOString() : null
            });
            break;
          }
          case "whitelistRevoke":
            for (const subjectId of request.subjectIds) await this.repos.whitelist.revokeSubject(guildId, subjectId, actor.userId, nowIso);
            break;
        }
      }
      this.policies.invalidate(guildId);
      for (const change of plan.changes) {
        await this.evidence.append({
          guildId,
          eventType: "config.changed",
          severity: change.weakening ? "high" : "medium",
          actorId: actor.userId,
          confidence: "high",
          action: change.label,
          actionResult: "applied",
          evidence: { ...change.evidence, weakening: change.weakening, access: actor.access }
        });
      }
      const lines = plan.changes.map((change) => `${change.weakening ? "⚠ " : ""}**${change.label}**: ${change.previous} → ${change.next}`);
      const description = [`Changed by ${userRef(actor.userId)}.`, "", ...lines].join("\n");
      const title = plan.weakening ? "Protection weakened" : "Configuration changed";
      await this.alerts.send({ guildId, severity: plan.weakening ? "high" : "medium", title, description });
      const current = (await this.policies.context(guildId)).policy.alertChannelId;
      if (previousAlertChannel && previousAlertChannel !== current) {
        await this.gateway.sendChannelMessage(guildId, previousAlertChannel, {
          embeds: [buildEmbed({ severity: "high", title: "Alerts moved", description: `${description}\n\nAlerts are no longer posted in this channel.`, timestamp: this.clock.now() })]
        });
      }
      return { ok: true, message: lines.join("\n") };
    } catch (error) {
      if (error instanceof ValidationError) return { ok: false, message: error.message };
      this.logger.error({ err: errorMessage(error), guildId }, "Settings commit failed");
      return { ok: false, message: "The change could not be saved; check the bot logs." };
    }
  }

  private async refused(guildId: string, actor: Actor, plan: ChangePlan, reason: string): Promise<void> {
    await this.evidence.append({
      guildId,
      eventType: "config.refused",
      severity: "medium",
      actorId: actor.userId,
      confidence: "high",
      evidence: { reason, access: actor.access, changes: plan.changes.map((change) => change.evidence) }
    });
    await this.alerts.send({
      guildId,
      severity: "medium",
      title: "Configuration change refused",
      description: `${userRef(actor.userId)} (${actor.access}) tried to change:\n${plan.changes.map((change) => `**${change.label}**: ${change.previous} → ${change.next}`).join("\n")}\n\n${reason}`
    });
  }

  private async validateAgainstGuild(
    definition: SettingDefinition,
    value: unknown,
    guild: GuildInfo,
    roles: RoleInfo[],
    channels: ChannelInfo[],
    context: PolicyContext
  ): Promise<void> {
    const { kind } = definition;
    const roleById = new Map(roles.map((role) => [role.id, role]));
    const channelIds = new Set(channels.map((channel) => channel.id));
    const checkRole = (roleId: string): RoleInfo => {
      const role = roleById.get(roleId);
      if (!role) throw new ValidationError(`${definition.label}: role ${roleId} does not exist`);
      if (role.isEveryone) throw new ValidationError(`${definition.label}: @everyone cannot be used here`);
      return role;
    };
    switch (kind.type) {
      case "channel":
        if (value === null) return;
        if (!channelIds.has(String(value))) throw new ValidationError(`${definition.label}: channel not found`);
        if (definition.path === "alertChannelId") {
          const check = await this.gateway.canSendIn(guild.id, String(value));
          if (!check.ok) throw new ValidationError(`Val Protection cannot post in <#${String(value)}>: ${check.reason ?? "missing permissions"}`);
        }
        return;
      case "channels":
        for (const channelId of value as string[]) if (!channelIds.has(channelId)) throw new ValidationError(`${definition.label}: channel ${channelId} not found`);
        return;
      case "role": {
        if (value === null) return;
        const role = checkRole(String(value));
        if (definition.path === "antiRaid.quarantineRoleId") this.checkQuarantineRole(role, guild, context);
        return;
      }
      case "roles":
        for (const roleId of value as string[]) {
          const role = checkRole(roleId);
          if (kind.noDangerousPermissions) {
            if (role.managed) throw new ValidationError(`${definition.label}: ${role.name} is managed by an integration`);
            const dangerous = dangerousBits(role.permissions, context.dangerousMask);
            if (dangerous !== 0n) throw new ValidationError(`${definition.label}: ${role.name} carries ${namesOf(dangerous).join(", ")}; a decoy role must have no privileges`);
            if (context.protectedRoles.has(roleId)) throw new ValidationError(`${definition.label}: ${role.name} is a protected role`);
          }
        }
        return;
      case "users":
        for (const userId of value as string[]) {
          if (userId === guild.botUserId) throw new ValidationError(`${definition.label}: Val Protection itself cannot be listed`);
          if (!kind.botsOnly && !kind.humansOnly) continue;
          const member = await this.gateway.getMember(guild.id, userId);
          if (!member) throw new ValidationError(`${definition.label}: ${userId} is not a member of this server`);
          if (kind.botsOnly && !member.isBot) throw new ValidationError(`${definition.label}: ${member.username} is not a bot`);
          if (kind.humansOnly && member.isBot) throw new ValidationError(`${definition.label}: ${member.username} is a bot`);
        }
        return;
      default:
        return;
    }
  }

  private checkQuarantineRole(role: RoleInfo, guild: GuildInfo, context: PolicyContext): void {
    if (role.managed) throw new ValidationError(`Quarantine role: ${role.name} is managed by an integration`);
    if (role.position >= guild.botHighestRolePosition) throw new ValidationError(`Quarantine role: move ${role.name} below Val Protection's role so it can be assigned`);
    const dangerous = dangerousBits(role.permissions, context.dangerousMask);
    if (dangerous !== 0n) throw new ValidationError(`Quarantine role: ${role.name} carries ${namesOf(dangerous).join(", ")}; it must not grant privileges`);
    if (context.protectedRoles.has(role.id)) throw new ValidationError(`Quarantine role: ${role.name} is a protected role`);
  }

  private async planProtectedRoles(context: PolicyContext, roleIds: string[], guild: GuildInfo, roles: RoleInfo[]): Promise<PlannedChange[]> {
    const wanted = [...new Set(roleIds)];
    const roleById = new Map(roles.map((role) => [role.id, role]));
    const policy: GuildPolicy = context.policy;
    for (const roleId of wanted) {
      const role = roleById.get(roleId);
      if (!role) throw new ValidationError(`Protected roles: role ${roleId} does not exist`);
      if (role.isEveryone) throw new ValidationError("Protected roles: @everyone cannot be protected; fix its permissions directly");
      if (policy.honeypot.decoyRoleIds.includes(roleId)) throw new ValidationError(`Protected roles: ${role.name} is a decoy role`);
      if (policy.antiRaid.quarantineRoleId === roleId) throw new ValidationError(`Protected roles: ${role.name} is the quarantine role`);
    }
    const existing = (await this.repos.protectedRoles.list(context.guildId)).map((record) => record.roleId);
    const added = wanted.filter((id) => !existing.includes(id));
    const removed = existing.filter((id) => !wanted.includes(id));
    if (added.length === 0 && removed.length === 0) return [];
    const notes = wanted.filter((id) => (roleById.get(id)?.position ?? 0) >= guild.botHighestRolePosition);
    return [
      {
        label: "Protected roles",
        previous: listText(existing, (id) => `<@&${id}>`),
        next: listText(wanted, (id) => `<@&${id}>`) + (notes.length > 0 ? ` (above Val Protection, cannot be revoked: ${notes.map((id) => `<@&${id}>`).join(", ")})` : ""),
        weakening: removed.length > 0,
        ownerOnly: false,
        evidence: { setting: "protectedRoles", added, removed }
      }
    ];
  }

  private async planGranters(context: PolicyContext, request: Extract<ChangeRequest, { kind: "roleGranters" }>, roles: RoleInfo[]): Promise<PlannedChange[]> {
    const existingRule = context.protectedRoles.get(request.roleId);
    if (!existingRule) {
      const target = roles.find((item) => item.id === request.roleId);
      if (!target) throw new ValidationError(`Role ${request.roleId} does not exist`);
      if (target.isEveryone) throw new ValidationError("@everyone cannot be protected; fix its permissions directly");
      if (context.policy.honeypot.decoyRoleIds.includes(target.id)) throw new ValidationError(`${target.name} is a decoy role`);
      if (context.policy.antiRaid.quarantineRoleId === target.id) throw new ValidationError(`${target.name} is the quarantine role`);
    }
    const rule = existingRule ?? { roleId: request.roleId, source: "discord" as const, allowedGranterIds: [], allowedGranterRoleIds: [] };
    for (const roleId of request.roleIds) {
      const role = roles.find((item) => item.id === roleId);
      if (!role || role.isEveryone) throw new ValidationError(`Granter roles: role ${roleId} cannot be used`);
    }
    const userIds = [...new Set(request.userIds)];
    const roleIds = [...new Set(request.roleIds)];
    const addedUsers = userIds.filter((id) => !rule.allowedGranterIds.includes(id));
    const addedRoles = roleIds.filter((id) => !rule.allowedGranterRoleIds.includes(id));
    const unchanged = JSON.stringify([...rule.allowedGranterIds].sort()) === JSON.stringify([...userIds].sort()) && JSON.stringify([...rule.allowedGranterRoleIds].sort()) === JSON.stringify([...roleIds].sort());
    if (existingRule && unchanged) return [];
    return [
      {
        label: existingRule ? `Granters of <@&${request.roleId}>` : `Protect <@&${request.roleId}>`,
        previous: existingRule ? `${listText(rule.allowedGranterIds, (id) => `<@${id}>`)} / roles: ${listText(rule.allowedGranterRoleIds, (id) => `<@&${id}>`)}` : "not protected",
        next: `${listText(userIds, (id) => `<@${id}>`)} / roles: ${listText(roleIds, (id) => `<@&${id}>`)}`,
        weakening: addedUsers.length > 0 || addedRoles.length > 0,
        ownerOnly: false,
        evidence: { setting: "roleGranters", roleId: request.roleId, userIds, roleIds }
      }
    ];
  }

  private async planWhitelistAdd(context: PolicyContext, guild: GuildInfo, actor: Actor, request: Extract<ChangeRequest, { kind: "whitelistAdd" }>): Promise<PlannedChange> {
    if (request.subjectId === actor.userId) throw new ValidationError("You cannot approve yourself");
    if (request.subjectId === guild.botUserId) throw new ValidationError("Val Protection does not need an approval");
    const reason = request.reason.trim();
    if (reason.length < 3) throw new ValidationError("Give a reason of at least 3 characters");
    if (request.hours !== null && (!Number.isInteger(request.hours) || request.hours < 1 || request.hours > 720)) throw new ValidationError("Duration must be between 1 and 720 hours");
    const member = await this.gateway.getMember(guild.id, request.subjectId);
    if (!member) throw new ValidationError("This account is not a member of the server");
    return {
      label: "Whitelist",
      previous: context.whitelist.some((entry) => entry.subjectId === request.subjectId) ? "already approved for other scopes" : "not approved",
      next: `<@${request.subjectId}> approved for \`${request.scope}\`${request.hours ? ` during ${request.hours}h` : " without expiry"} (${reason.slice(0, 120)})`,
      weakening: true,
      ownerOnly: request.scope === "all",
      evidence: { action: "whitelist.add", subjectId: request.subjectId, scope: request.scope, hours: request.hours, reason }
    };
  }
}
