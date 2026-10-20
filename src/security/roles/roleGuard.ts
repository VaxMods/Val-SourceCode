import { AuditLogEvent } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { atLeastConfidence, type ActionRecord, type Confidence, type Severity } from "../../core/types.js";
import { findChange, rolesFromChange, auditConfidence, type AuditEvent } from "../../discord/auditEvent.js";
import type { DiscordGateway, GuildInfo, MemberInfo, RoleInfo } from "../../discord/gateway.js";
import { ADMINISTRATOR, ROLE_MANAGEMENT_PERMISSIONS, dangerousBits, namesOf, parseBits, permissionSeverity } from "../../discord/permissions.js";
import { roleRef, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import { canEditRolePermissions, canManageRole } from "../hierarchy.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { LockManager } from "../infra/lockManager.js";
import type { LockdownService } from "../lockdown/lockdownService.js";
import { authorizeRoleGrant, trustActor, type GrantAuthorization } from "../policy/authorization.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip, type ContainmentResponder } from "../response/containment.js";

export interface HoneypotRoleHooks {
  onDecoyRoleGranted(guildId: string, recipientId: string, actorId: string | null, roleId: string): Promise<void>;
  onDecoyRolePermissionChange(guildId: string, actorId: string | null, role: RoleInfo, previous: bigint): Promise<void>;
}

export interface GrantInput {
  guildId: string;
  targetId: string;
  roleIds: string[];
  actorId: string | null;
  confidence: Confidence;
  source: "audit" | "audit-fetch" | "member-update";
  auditEntryId: string | null;
}

export interface GrantDecision {
  roleId: string;
  sensitive: boolean;
  authorization: GrantAuthorization;
  incidentId: string | null;
  actions: ActionRecord[];
}

export class RoleGuard {
  private readonly auditHandled = new Map<string, number>();

  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly responder: ContainmentResponder,
    private readonly lockdown: LockdownService,
    private readonly locks: LockManager,
    private readonly honeypot: HoneypotRoleHooks,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  async onAuditEvent(event: AuditEvent): Promise<void> {
    switch (event.actionType) {
      case AuditLogEvent.MemberRoleUpdate: {
        const added = rolesFromChange(event, "$add").map((role) => role.id);
        if (added.length === 0 || !event.targetId) return;
        await this.handleGrant({
          guildId: event.guildId,
          targetId: event.targetId,
          roleIds: added,
          actorId: event.executorId,
          confidence: auditConfidence(event),
          source: event.source === "gateway" ? "audit" : "audit-fetch",
          auditEntryId: event.id
        });
        return;
      }
      case AuditLogEvent.RoleUpdate:
      case AuditLogEvent.RoleCreate:
        await this.handlePermissionChange(event);
        return;
      default:
        return;
    }
  }

  async onMemberRolesAdded(guildId: string, memberId: string, addedRoleIds: string[]): Promise<GrantDecision[]> {
    const context = await this.policies.context(guildId);
    if (!context.policy.roleProtection.enabled && context.policy.honeypot.decoyRoleIds.length === 0) return [];
    const relevant: string[] = [];
    for (const roleId of addedRoleIds) {
      if (context.policy.honeypot.decoyRoleIds.includes(roleId) || context.protectedRoles.has(roleId)) {
        relevant.push(roleId);
        continue;
      }
      const role = await this.gateway.getRole(guildId, roleId);
      if (role && dangerousBits(role.permissions, context.dangerousMask) !== 0n) relevant.push(roleId);
    }
    if (relevant.length === 0) return [];
    const observedAt = this.clock.now();
    await this.clock.sleep(context.policy.roleProtection.correlationDelayMs);
    const pending = relevant.filter((roleId) => (this.auditHandled.get(`${guildId}:${memberId}:${roleId}`) ?? 0) < observedAt - 2000);
    if (pending.length === 0) return [];
    const attribution = await this.attribute(guildId, memberId, pending, context.policy.roleProtection.correlationWindowSeconds * 1000);
    return this.handleGrant({ guildId, targetId: memberId, roleIds: pending, ...attribution, source: attribution.source });
  }

  async onRolePositionChanged(guildId: string, role: RoleInfo, oldPosition: number): Promise<void> {
    const guild = await this.gateway.getGuild(guildId);
    if (!guild || role.botId === guild.botUserId) return;
    if (!(oldPosition < guild.botHighestRolePosition && role.position >= guild.botHighestRolePosition)) return;
    const context = await this.policies.context(guildId);
    const sensitive = context.protectedRoles.has(role.id) || dangerousBits(role.permissions, context.dangerousMask) !== 0n;
    if (!sensitive || !(await this.locks.once(`role-above-bot:${guildId}:${role.id}`, 3600000))) return;
    await this.incidents.open({
      guildId,
      type: "role.hierarchy-change",
      severity: "medium",
      actorId: null,
      targetId: role.id,
      confidence: "high",
      status: "needs-review",
      summary: `Sensitive role ${roleRef(role.id)} was moved above Val Protection's highest role. Val Protection can no longer revoke it. Move Val Protection's role back above it if this was not intended.`,
      details: { roleName: role.name, oldPosition, newPosition: role.position, botHighestRolePosition: guild.botHighestRolePosition }
    });
  }

  async handleGrant(input: GrantInput): Promise<GrantDecision[]> {
    const context = await this.policies.context(input.guildId);
    const guild = await this.gateway.getGuild(input.guildId);
    if (!guild) return [];
    if (input.actorId && input.actorId === guild.botUserId) return [];
    const decisions: GrantDecision[] = [];
    for (const roleId of input.roleIds) {
      if (input.auditEntryId) {
        if (!(await this.locks.once(`grant:${input.guildId}:${input.targetId}:${roleId}:${input.auditEntryId}`, 600000))) continue;
        this.markAuditHandled(`${input.guildId}:${input.targetId}:${roleId}`);
      }
      const decision = await this.handleSingleGrant(context, guild, input, roleId);
      if (decision) decisions.push(decision);
    }
    return decisions;
  }

  private async handleSingleGrant(context: PolicyContext, guild: GuildInfo, input: GrantInput, roleId: string): Promise<GrantDecision | null> {
    const role = await this.gateway.getRole(input.guildId, roleId);
    if (!role) return null;
    const dangerous = dangerousBits(role.permissions, context.dangerousMask);
    if (context.policy.honeypot.enabled && context.policy.honeypot.decoyRoleIds.includes(roleId) && dangerous === 0n) {
      await this.honeypot.onDecoyRoleGranted(input.guildId, input.targetId, input.actorId, roleId);
      return null;
    }
    if (!context.policy.roleProtection.enabled) return null;
    const rule = context.protectedRoles.get(roleId);
    const sensitive = rule !== undefined || (context.policy.roleProtection.treatDangerousRolesAsProtected && dangerous !== 0n);
    if (!sensitive) return null;
    const target = await this.gateway.getMember(input.guildId, input.targetId);
    const actorMember = input.actorId ? await this.gateway.getMember(input.guildId, input.actorId) : null;
    const authorization = authorizeRoleGrant(context, guild, input.actorId, actorMember, rule, this.lockdown.isActive(input.guildId));
    const evidence = {
      roleName: role.name,
      rolePermissions: namesOf(role.permissions),
      dangerousPermissions: namesOf(dangerous),
      protectedBy: rule ? rule.source : "dangerous-permissions",
      source: input.source,
      auditEntryId: input.auditEntryId,
      authorization: authorization.reason,
      recipientStillHasRole: target?.roleIds.includes(roleId) ?? false
    };
    if (authorization.status === "authorized") {
      await this.evidence.append({
        guildId: input.guildId,
        eventType: "role.grant.authorized",
        severity: "info",
        actorId: input.actorId,
        targetId: input.targetId,
        confidence: input.confidence,
        evidence: { ...evidence, roleId }
      });
      return { roleId, sensitive, authorization, incidentId: null, actions: [] };
    }
    const severity: Severity = (role.permissions & ADMINISTRATOR) === ADMINISTRATOR ? "critical" : permissionSeverity(dangerous) === "critical" ? "critical" : "high";
    const unknown = authorization.status === "unknown";
    const summary = unknown
      ? `Sensitive role ${roleRef(role.id)} was granted to ${userRef(input.targetId)} but the granter could not be identified. Human review is required; no automatic revocation is performed against an unknown author.`
      : `${userRef(input.actorId)} granted sensitive role ${roleRef(role.id)} to ${userRef(input.targetId)}. This grant is not allowed by the security policy: ${authorization.reason}.`;
    const incident = await this.incidents.open({
      guildId: input.guildId,
      type: unknown ? "role.grant-unattributed" : "role.unauthorized-grant",
      severity,
      actorId: input.actorId,
      targetId: input.targetId,
      confidence: input.confidence,
      summary,
      details: { ...evidence, roleId },
      fields: [
        { name: "Role", value: `${role.name} (${role.id})`, inline: true },
        { name: "Recipient", value: userRef(input.targetId), inline: true },
        { name: "Dangerous permissions", value: namesOf(dangerous).join(", ") || "protected role", inline: false }
      ]
    });
    const actions: ActionRecord[] = [];
    actions.push(await this.revokeFromRecipient(context, guild, input, role, target, authorization));
    actions.push(...(await this.respondToGranter(context, guild, input, actorMember, authorization, incident.id)));
    await this.incidents.recordActions(incident, actions);
    return { roleId, sensitive, authorization, incidentId: incident.id, actions };
  }

  private async revokeFromRecipient(
    context: PolicyContext,
    guild: GuildInfo,
    input: GrantInput,
    role: RoleInfo,
    target: MemberInfo | null,
    authorization: GrantAuthorization
  ): Promise<ActionRecord> {
    const action = "revoke-role-from-recipient";
    const settings = context.policy.roleProtection;
    if (!settings.revokeFromRecipient) return skip(action, input.targetId, "roleProtection.revokeFromRecipient is disabled");
    if (context.policy.mode !== "automatic") return skip(action, input.targetId, "monitor mode: revocation recommended, not executed");
    if (authorization.status === "unknown" && !settings.revokeWhenActorUnknown) {
      return skip(action, input.targetId, "granter unknown; revocation requires human confirmation");
    }
    if (authorization.status === "unauthorized" && !atLeastConfidence(input.confidence, settings.minConfidenceToRevoke)) {
      return skip(action, input.targetId, `attribution confidence ${input.confidence} is below ${settings.minConfidenceToRevoke}`);
    }
    if (!target) return skip(action, input.targetId, "recipient is no longer in the server");
    if (!target.roleIds.includes(role.id)) return skip(action, input.targetId, "recipient no longer holds the role");
    if (target.isOwner) return skip(action, input.targetId, "the recipient is the server owner");
    const capability = canManageRole(guild, role);
    if (!capability.ok) return skip(action, input.targetId, `${capability.reason}. Remove the role manually.`);
    const outcome = await this.gateway.removeMemberRoles(input.guildId, input.targetId, [role.id], `Val Protection: unauthorized grant of protected role ${role.name}`);
    return { action, target: input.targetId, rationale: `role ${role.name} was granted without authorization (${authorization.reason})`, outcome };
  }

  private async respondToGranter(
    context: PolicyContext,
    guild: GuildInfo,
    input: GrantInput,
    actorMember: MemberInfo | null,
    authorization: GrantAuthorization,
    incidentId: string
  ): Promise<ActionRecord[]> {
    const action = "restrict-granter-role-management";
    const settings = context.policy.roleProtection;
    if (authorization.status !== "unauthorized" || !input.actorId) return [];
    if (settings.granterResponse === "none") return [skip(action, input.actorId, "roleProtection.granterResponse is none")];
    if (context.policy.mode !== "automatic") return [skip(action, input.actorId, "monitor mode: restriction recommended, not executed")];
    if (input.confidence !== "high") return [skip(action, input.actorId, "the granter is only restricted when attribution confidence is high")];
    if (input.actorId === guild.ownerId) return [skip(action, input.actorId, "the granter is the server owner")];
    if (actorMember?.isBot) {
      return [skip(action, input.actorId, "the granter is a bot or integration; review it and remove it if it is not trusted")];
    }
    return this.responder.stripPermissionRoles(
      input.guildId,
      input.actorId,
      ROLE_MANAGEMENT_PERMISSIONS,
      `Val Protection: unauthorized grant of a protected role (incident ${incidentId})`
    );
  }

  private async handlePermissionChange(event: AuditEvent): Promise<void> {
    if (!event.targetId) return;
    const context = await this.policies.context(event.guildId);
    const guild = await this.gateway.getGuild(event.guildId);
    if (!guild || event.executorId === guild.botUserId) return;
    const change = findChange(event, "permissions");
    if (!change) return;
    const previous = event.actionType === AuditLogEvent.RoleCreate ? 0n : parseBits(change.old) ?? 0n;
    const next = parseBits(change.new);
    if (next === null) return;
    const gained = next & ~previous;
    if (gained === 0n) return;
    const role = await this.gateway.getRole(event.guildId, event.targetId);
    if (!role) return;
    if (context.policy.honeypot.enabled && context.policy.honeypot.decoyRoleIds.includes(role.id)) {
      await this.honeypot.onDecoyRolePermissionChange(event.guildId, event.executorId, role, previous);
      return;
    }
    if (!context.policy.roleProtection.enabled) return;
    const gainedDangerous = dangerousBits(gained, context.dangerousMask) & gained;
    const adminGained = (gained & ADMINISTRATOR) === ADMINISTRATOR;
    if (gainedDangerous === 0n && !adminGained) return;
    const confidence = auditConfidence(event);
    const trust = trustActor(context, guild, event.executorId, "roles");
    const evidence = {
      roleName: role.name,
      managedBotRole: role.managed,
      gainedPermissions: namesOf(gained),
      gainedDangerous: namesOf(gainedDangerous | (adminGained ? ADMINISTRATOR : 0n)),
      previous: previous.toString(),
      next: next.toString(),
      auditEntryId: event.id,
      created: event.actionType === AuditLogEvent.RoleCreate,
      trust: trust.reason
    };
    if (trust.trusted) {
      await this.evidence.append({ guildId: event.guildId, eventType: "role.permissions.authorized-change", severity: "low", actorId: event.executorId, targetId: role.id, confidence, evidence });
      return;
    }
    const incident = await this.incidents.open({
      guildId: event.guildId,
      type: event.actionType === AuditLogEvent.RoleCreate ? "role.privileged-creation" : "role.permission-escalation",
      severity: adminGained ? "critical" : "high",
      actorId: event.executorId,
      targetId: role.id,
      confidence,
      summary: `${userRef(event.executorId)} gave role ${roleRef(role.id)} new dangerous permissions (${evidence.gainedDangerous.join(", ")})${role.managed ? " on a bot's managed role" : ""}. ${trust.reason}.`,
      details: evidence
    });
    const actions: ActionRecord[] = [];
    const settings = context.policy.roleProtection;
    const revertAction = "revert-dangerous-permissions";
    const removeBits = gainedDangerous | (adminGained ? ADMINISTRATOR : 0n);
    const desired = role.permissions & ~removeBits;
    if (!settings.revertUnauthorizedPermissionChanges) actions.push(skip(revertAction, role.id, "roleProtection.revertUnauthorizedPermissionChanges is disabled"));
    else if (context.policy.mode !== "automatic") actions.push(skip(revertAction, role.id, "monitor mode: revert recommended, not executed"));
    else if (!atLeastConfidence(confidence, settings.minConfidenceToRevoke)) actions.push(skip(revertAction, role.id, `attribution confidence ${confidence} is below ${settings.minConfidenceToRevoke}`));
    else {
      const capability = canEditRolePermissions(guild, role, desired);
      if (!capability.ok) actions.push(skip(revertAction, role.id, `${capability.reason}. Remove ${evidence.gainedDangerous.join(", ")} from the role manually.`));
      else {
        const outcome = await this.gateway.setRolePermissions(event.guildId, role.id, desired, `Val Protection: unauthorized permission escalation (incident ${incident.id})`);
        actions.push({ action: revertAction, target: role.id, rationale: "remove only the dangerous permissions that were just added", outcome });
      }
    }
    if (event.executorId) {
      actions.push(
        ...(await this.respondToGranter(
          context,
          guild,
          { guildId: event.guildId, targetId: role.id, roleIds: [role.id], actorId: event.executorId, confidence, source: "audit", auditEntryId: event.id },
          await this.gateway.getMember(event.guildId, event.executorId),
          { status: "unauthorized", reason: trust.reason },
          incident.id
        ))
      );
    }
    await this.incidents.recordActions(incident, actions);
  }

  private markAuditHandled(key: string): void {
    const now = this.clock.now();
    this.auditHandled.set(key, now);
    if (this.auditHandled.size > 10000) {
      for (const [entry, at] of this.auditHandled) if (at < now - 600000) this.auditHandled.delete(entry);
    }
  }

  private async attribute(
    guildId: string,
    memberId: string,
    roleIds: string[],
    windowMs: number
  ): Promise<{ actorId: string | null; confidence: Confidence; auditEntryId: string | null; source: GrantInput["source"] }> {
    const entries = await this.gateway.findAuditEvents(guildId, AuditLogEvent.MemberRoleUpdate, 25);
    const now = this.clock.now();
    const matches = entries.filter(
      (entry) =>
        entry.targetId === memberId &&
        now - entry.createdAt <= windowMs &&
        rolesFromChange(entry, "$add").some((role) => roleIds.includes(role.id))
    );
    if (matches.length === 0) {
      this.logger.warn({ guildId, memberId, roleIds }, "Sensitive role grant without matching audit log entry");
      return { actorId: null, confidence: "none", auditEntryId: null, source: "member-update" };
    }
    const executors = new Set(matches.map((entry) => entry.executorId));
    const latest = matches.reduce((a, b) => (a.createdAt >= b.createdAt ? a : b));
    if (executors.size === 1 && latest.executorId) {
      return { actorId: latest.executorId, confidence: "high", auditEntryId: latest.id, source: "audit-fetch" };
    }
    return { actorId: latest.executorId, confidence: "low", auditEntryId: latest.id, source: "audit-fetch" };
  }
}
