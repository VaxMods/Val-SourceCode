import crypto from "node:crypto";
import { ChannelType } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { ActionRecord } from "../../core/types.js";
import { toJson } from "../../database/json.js";
import type { SnapshotRepository, SnapshotSummary } from "../../database/repositories/snapshotRepository.js";
import type { ChannelInfo, DiscordGateway, RoleInfo } from "../../discord/gateway.js";
import { ADMINISTRATOR, namesOf } from "../../discord/permissions.js";
import type { RecoveryAdvisor } from "../antiNuke/antiNukeService.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import type { LockManager } from "../infra/lockManager.js";
import type { LockdownService } from "../lockdown/lockdownService.js";
import type { PolicyService } from "../policy/policyService.js";
import { skip } from "../response/containment.js";

export interface RoleSnapshot {
  id: string;
  name: string;
  permissions: string;
  position: number;
  color: number;
  hoist: boolean;
  mentionable: boolean;
  managed: boolean;
  isEveryone: boolean;
}

export interface ChannelSnapshot {
  id: string;
  name: string;
  type: number;
  parentId: string | null;
  position: number;
  topic: string | null;
  nsfw: boolean;
  rateLimitPerUser: number;
  bitrate: number | null;
  userLimit: number | null;
  overwrites: Array<{ id: string; type: "role" | "member"; allow: string; deny: string }>;
}

export interface GuildSnapshotData {
  version: 1;
  guildId: string;
  capturedAt: string;
  roles: RoleSnapshot[];
  channels: ChannelSnapshot[];
}

export interface RecoveryPlan {
  snapshotId: string;
  snapshotAt: string;
  integrity: boolean;
  missingRoles: RoleSnapshot[];
  missingChannels: ChannelSnapshot[];
  permissionDrift: Array<{ roleId: string; name: string; added: string[]; removed: string[] }>;
  limitations: string[];
}

export const RECOVERY_LIMITATIONS = [
  "Deleted objects cannot be undeleted: recreated roles and channels get new IDs.",
  "Messages, threads, pins, webhooks, invites and integrations are not restored.",
  "Member role assignments are not restored; reassign recreated roles manually.",
  "Discord only lets Val Protection grant permissions it holds itself; any other permission is dropped and listed.",
  "Channel order is approximate."
];

function roleSnapshot(role: RoleInfo): RoleSnapshot {
  return {
    id: role.id,
    name: role.name,
    permissions: role.permissions.toString(),
    position: role.position,
    color: role.color,
    hoist: role.hoist,
    mentionable: role.mentionable,
    managed: role.managed,
    isEveryone: role.isEveryone
  };
}

function channelSnapshot(channel: ChannelInfo): ChannelSnapshot {
  return {
    id: channel.id,
    name: channel.name,
    type: channel.type,
    parentId: channel.parentId,
    position: channel.position,
    topic: channel.topic,
    nsfw: channel.nsfw,
    rateLimitPerUser: channel.rateLimitPerUser,
    bitrate: channel.bitrate,
    userLimit: channel.userLimit,
    overwrites: channel.overwrites.map((item) => ({ id: item.id, type: item.type, allow: item.allow.toString(), deny: item.deny.toString() }))
  };
}

export class SnapshotService implements RecoveryAdvisor {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly repo: SnapshotRepository,
    private readonly policies: PolicyService,
    private readonly evidence: EvidenceSink,
    private readonly lockdown: LockdownService,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  async capture(guildId: string, reason: "scheduled" | "manual" | "startup"): Promise<SnapshotSummary | null> {
    if (reason === "scheduled" && this.lockdown.isActive(guildId)) return null;
    const guild = await this.gateway.getGuild(guildId);
    if (!guild) return null;
    const [roles, channels] = await Promise.all([this.gateway.listRoles(guildId), this.gateway.listChannels(guildId)]);
    const now = this.clock.now();
    const data: GuildSnapshotData = {
      version: 1,
      guildId,
      capturedAt: new Date(now).toISOString(),
      roles: roles.map(roleSnapshot),
      channels: channels.map(channelSnapshot)
    };
    const raw = toJson(data);
    const summary: SnapshotSummary = {
      id: `SNAP-${crypto.randomBytes(4).toString("hex").toUpperCase()}`,
      guildId,
      createdAt: data.capturedAt,
      hash: crypto.createHash("sha256").update(raw).digest("hex"),
      roleCount: roles.length,
      channelCount: channels.length
    };
    await this.repo.insert(summary, data);
    const context = await this.policies.context(guildId);
    await this.repo.prune(guildId, context.policy.backups.keep);
    await this.evidence.append({ guildId, eventType: "backup.snapshot", severity: "info", evidence: { snapshotId: summary.id, reason, roles: roles.length, channels: channels.length, hash: summary.hash } });
    return summary;
  }

  async captureDue(guildIds: readonly string[]): Promise<void> {
    const now = this.clock.now();
    for (const guildId of guildIds) {
      try {
        const context = await this.policies.context(guildId);
        if (!context.policy.backups.enabled) continue;
        const [latest] = await this.repo.list(guildId, 1);
        if (latest && now - Date.parse(latest.createdAt) < context.policy.backups.intervalMinutes * 60000) continue;
        await this.capture(guildId, latest ? "scheduled" : "startup");
      } catch (error) {
        this.logger.error({ err: errorMessage(error), guildId }, "Snapshot failed");
      }
    }
  }

  async list(guildId: string, limit = 10): Promise<SnapshotSummary[]> {
    return this.repo.list(guildId, limit);
  }

  async describe(guildId: string): Promise<string | null> {
    try {
      const [latest] = await this.repo.list(guildId, 1);
      if (!latest) return "No structural snapshot is available, so deleted objects must be recreated manually.";
      return `Deleted objects cannot be undeleted. The structural snapshot ${latest.id} from ${latest.createdAt} can recreate missing roles and channels (new IDs, no messages) with /security recover once the attack is contained.`;
    } catch {
      return null;
    }
  }

  async plan(guildId: string, snapshotId?: string): Promise<RecoveryPlan | null> {
    const id = snapshotId ?? (await this.repo.list(guildId, 1))[0]?.id;
    if (!id) return null;
    const loaded = await this.repo.load<GuildSnapshotData>(guildId, id);
    if (!loaded || !loaded.data) return null;
    const integrity = crypto.createHash("sha256").update(loaded.raw).digest("hex") === loaded.summary.hash;
    const [roles, channels] = await Promise.all([this.gateway.listRoles(guildId), this.gateway.listChannels(guildId)]);
    const currentRoles = new Map(roles.map((role) => [role.id, role]));
    const currentChannels = new Set(channels.map((channel) => channel.id));
    const missingRoles = loaded.data.roles.filter((role) => !role.managed && !role.isEveryone && !currentRoles.has(role.id));
    const missingChannels = loaded.data.channels.filter((channel) => !currentChannels.has(channel.id));
    const permissionDrift = loaded.data.roles
      .filter((role) => currentRoles.has(role.id))
      .map((role) => {
        const before = BigInt(role.permissions);
        const now = (currentRoles.get(role.id) as RoleInfo).permissions;
        return { roleId: role.id, name: role.name, added: namesOf(now & ~before), removed: namesOf(before & ~now) };
      })
      .filter((item) => item.added.length > 0 || item.removed.length > 0);
    return { snapshotId: id, snapshotAt: loaded.summary.createdAt, integrity, missingRoles, missingChannels, permissionDrift, limitations: RECOVERY_LIMITATIONS };
  }

  async execute(guildId: string, plan: RecoveryPlan, requestedBy: string): Promise<ActionRecord[]> {
    return this.locks.withLock(`recovery:${guildId}`, 600000, async () => {
      if (!plan.integrity) return [skip("recover", guildId, "snapshot integrity check failed; refusing to restore from it")];
      const guild = await this.gateway.getGuild(guildId);
      if (!guild) return [skip("recover", guildId, "guild unavailable")];
      const isAdmin = (guild.botPermissions & ADMINISTRATOR) === ADMINISTRATOR;
      const allowed = (bits: bigint) => (isAdmin ? bits : bits & guild.botPermissions);
      const actions: ActionRecord[] = [];
      const roleMap = new Map<string, string>();
      const reason = `Val Protection recovery from ${plan.snapshotId} requested by ${requestedBy}`;
      for (const role of [...plan.missingRoles].sort((a, b) => a.position - b.position)) {
        const wanted = BigInt(role.permissions);
        const granted = allowed(wanted);
        const dropped = wanted & ~granted;
        const outcome = await this.gateway.createRole(guildId, { name: role.name, permissions: granted, color: role.color, hoist: role.hoist, mentionable: role.mentionable }, reason);
        if (outcome.ok && outcome.id) roleMap.set(role.id, outcome.id);
        actions.push({
          action: "recreate-role",
          target: outcome.id ?? role.id,
          rationale: `recreate "${role.name}"${dropped !== 0n ? `; permissions not restorable by the bot: ${namesOf(dropped).join(", ")}` : ""}`,
          outcome
        });
      }
      const channelMap = new Map<string, string>();
      const missingRoleIds = new Set(plan.missingRoles.map((role) => role.id));
      const missingChannelIds = new Set(plan.missingChannels.map((channel) => channel.id));
      const ordered = [...plan.missingChannels].sort(
        (a, b) => (a.type === ChannelType.GuildCategory ? 0 : 1) - (b.type === ChannelType.GuildCategory ? 0 : 1) || a.position - b.position
      );
      for (const channel of ordered) {
        const overwrites = channel.overwrites.flatMap((item) => {
          if (item.type === "role" && missingRoleIds.has(item.id)) {
            const mapped = roleMap.get(item.id);
            return mapped ? [{ ...item, id: mapped }] : [];
          }
          return [item];
        });
        let parentId = channel.parentId;
        if (parentId && missingChannelIds.has(parentId)) parentId = channelMap.get(parentId) ?? null;
        const outcome = await this.gateway.createChannel(
          guildId,
          {
            name: channel.name,
            type: channel.type,
            parentId,
            topic: channel.topic,
            nsfw: channel.nsfw,
            rateLimitPerUser: channel.rateLimitPerUser,
            bitrate: channel.bitrate,
            userLimit: channel.userLimit,
            overwrites: overwrites.map((item) => ({ id: item.id, type: item.type, allow: allowed(BigInt(item.allow)), deny: allowed(BigInt(item.deny)) }))
          },
          reason
        );
        if (outcome.ok && outcome.id) channelMap.set(channel.id, outcome.id);
        actions.push({ action: "recreate-channel", target: outcome.id ?? channel.id, rationale: `recreate #${channel.name} (content is not restorable)`, outcome });
      }
      await this.evidence.append({
        guildId,
        eventType: "recovery.executed",
        severity: "medium",
        actorId: requestedBy,
        action: "recover",
        actionResult: actions.every((item) => item.outcome.ok) ? "success" : "partial",
        evidence: {
          snapshotId: plan.snapshotId,
          rolesRecreated: [...roleMap.entries()],
          channelsRecreated: [...channelMap.entries()],
          failures: actions.filter((item) => !item.outcome.ok).map((item) => ({ action: item.action, error: item.outcome.error ?? item.outcome.detail ?? null }))
        }
      });
      return actions;
    });
  }
}
