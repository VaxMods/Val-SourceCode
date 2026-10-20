import {
  AttachmentBuilder,
  ChannelType,
  GuildFeature,
  OverwriteType,
  PermissionFlagsBits,
  UserFlags,
  type AuditLogEvent,
  type Client,
  type Guild,
  type GuildBasedChannel,
  type GuildMember,
  type Role
} from "discord.js";
import type { Logger } from "pino";
import { discordErrorCode, errorMessage } from "../core/errors.js";
import type { ActionOutcome } from "../core/types.js";
import { normalizeAuditEntry, type AuditEvent } from "./auditEvent.js";
import type {
  ChannelCreateSpec,
  ChannelInfo,
  CreateOutcome,
  DiscordGateway,
  GuildInfo,
  InvitePauseOutcome,
  MemberInfo,
  OutgoingMessage,
  RoleCreateSpec,
  RoleInfo
} from "./gateway.js";

const UNKNOWN_MEMBER = 10007;
const UNKNOWN_ROLE = 10011;
const MAX_INCIDENT_ACTION_MS = 24 * 3600000 - 60000;
const TEXT_LIKE = new Set<number>([ChannelType.GuildText, ChannelType.GuildAnnouncement, ChannelType.GuildForum, ChannelType.GuildMedia]);
const VOICE_LIKE = new Set<number>([ChannelType.GuildVoice, ChannelType.GuildStageVoice]);

export class DiscordJsGateway implements DiscordGateway {
  constructor(
    private readonly client: Client<true>,
    private readonly logger: Logger
  ) {}

  async getGuild(guildId: string): Promise<GuildInfo | null> {
    const guild = this.guildOf(guildId);
    if (!guild) return null;
    const me = guild.members.me ?? (await guild.members.fetchMe().catch(() => null));
    if (!me) return null;
    const incidentUntil = guild.incidentsData?.invitesDisabledUntil?.getTime() ?? 0;
    return {
      id: guild.id,
      name: guild.name,
      ownerId: guild.ownerId,
      botUserId: this.client.user.id,
      botHighestRolePosition: me.roles.highest.position,
      botPermissions: me.permissions.bitfield,
      verificationLevel: guild.verificationLevel,
      mfaLevel: guild.mfaLevel,
      explicitContentFilter: guild.explicitContentFilter,
      invitesPaused: guild.features.includes(GuildFeature.InvitesDisabled) || incidentUntil > Date.now(),
      memberCount: guild.memberCount
    };
  }

  async getRole(guildId: string, roleId: string): Promise<RoleInfo | null> {
    const guild = this.guildOf(guildId);
    if (!guild) return null;
    try {
      const role = guild.roles.cache.get(roleId) ?? (await guild.roles.fetch(roleId));
      return role ? this.toRole(guild, role) : null;
    } catch (error) {
      if (discordErrorCode(error) !== UNKNOWN_ROLE) this.logger.warn({ err: errorMessage(error), guildId, roleId }, "Role lookup failed");
      return null;
    }
  }

  async listRoles(guildId: string): Promise<RoleInfo[]> {
    const guild = this.guildOf(guildId);
    if (!guild) return [];
    return [...guild.roles.cache.values()].map((role) => this.toRole(guild, role));
  }

  async getMember(guildId: string, userId: string): Promise<MemberInfo | null> {
    const guild = this.guildOf(guildId);
    if (!guild) return null;
    try {
      const member = await guild.members.fetch(userId);
      return this.toMember(guild, member);
    } catch (error) {
      if (discordErrorCode(error) !== UNKNOWN_MEMBER) this.logger.warn({ err: errorMessage(error), guildId, userId }, "Member lookup failed");
      return null;
    }
  }

  async listMembers(guildId: string, limit: number): Promise<MemberInfo[] | null> {
    const guild = this.guildOf(guildId);
    if (!guild || guild.memberCount > limit) return null;
    try {
      const members = await guild.members.fetch({ time: 60000 });
      return [...members.values()].map((member) => this.toMember(guild, member));
    } catch (error) {
      this.logger.warn({ err: errorMessage(error), guildId }, "Member list fetch failed");
      return null;
    }
  }

  async listChannels(guildId: string): Promise<ChannelInfo[]> {
    const guild = this.guildOf(guildId);
    if (!guild) return [];
    const channels: ChannelInfo[] = [];
    for (const channel of guild.channels.cache.values()) {
      if (channel.isThread()) continue;
      channels.push(this.toChannel(channel));
    }
    return channels;
  }

  async findAuditEvents(guildId: string, actionType: number, limit: number): Promise<AuditEvent[]> {
    const guild = this.guildOf(guildId);
    if (!guild) return [];
    try {
      const logs = await guild.fetchAuditLogs({ type: actionType as AuditLogEvent, limit: Math.min(100, Math.max(1, limit)) });
      return [...logs.entries.values()].map((entry) =>
        normalizeAuditEntry(
          {
            id: entry.id,
            action: entry.action,
            executorId: entry.executorId,
            targetId: entry.targetId,
            reason: entry.reason,
            changes: entry.changes,
            extra: entry.extra,
            createdTimestamp: entry.createdTimestamp
          },
          guildId,
          "fetch"
        )
      );
    } catch (error) {
      this.logger.warn({ err: errorMessage(error), guildId, actionType }, "Audit log fetch failed");
      return [];
    }
  }

  async addMemberRole(guildId: string, userId: string, roleId: string, reason: string): Promise<ActionOutcome> {
    return this.run("add-member-role", guildId, async (guild) => {
      const member = await guild.members.fetch(userId);
      await member.roles.add(roleId, reason);
    });
  }

  async removeMemberRoles(guildId: string, userId: string, roleIds: string[], reason: string): Promise<ActionOutcome> {
    return this.run("remove-member-roles", guildId, async (guild) => {
      const member = await guild.members.fetch(userId);
      await member.roles.remove(roleIds, reason);
    });
  }

  async setRolePermissions(guildId: string, roleId: string, permissions: bigint, reason: string): Promise<ActionOutcome> {
    return this.run("set-role-permissions", guildId, async (guild) => {
      await guild.roles.edit(roleId, { permissions, reason });
    });
  }

  async kickMember(guildId: string, userId: string, reason: string): Promise<ActionOutcome> {
    return this.run("kick-member", guildId, async (guild) => {
      await guild.members.kick(userId, reason);
    });
  }

  async timeoutMember(guildId: string, userId: string, durationMs: number, reason: string): Promise<ActionOutcome> {
    return this.run("timeout-member", guildId, async (guild) => {
      const member = await guild.members.fetch(userId);
      await member.timeout(Math.min(durationMs, 28 * 24 * 3600000), reason);
    });
  }

  async deleteWebhook(guildId: string, webhookId: string, reason: string): Promise<ActionOutcome> {
    return this.run("delete-webhook", guildId, async () => {
      const webhook = await this.client.fetchWebhook(webhookId);
      if (webhook.guildId !== guildId) throw new Error("Webhook belongs to another guild");
      await webhook.delete(reason);
    });
  }

  async setVerificationLevel(guildId: string, level: number, reason: string): Promise<ActionOutcome> {
    return this.run("set-verification-level", guildId, async (guild) => {
      await guild.setVerificationLevel(level, reason);
    });
  }

  async pauseInvites(guildId: string, untilMs: number | null, reason: string): Promise<InvitePauseOutcome> {
    const guild = this.guildOf(guildId);
    if (!guild) return { ok: false, action: "pause-invites", error: "guild unavailable" };
    try {
      const until = untilMs === null ? null : new Date(Math.min(untilMs, Date.now() + MAX_INCIDENT_ACTION_MS));
      await guild.setIncidentActions({ invitesDisabledUntil: until });
      return { ok: true, action: "pause-invites", method: "incident-actions", detail: until ? `invites paused until ${until.toISOString()}` : "invites resumed" };
    } catch (error) {
      this.logger.warn({ err: errorMessage(error), guildId }, "Incident actions unavailable; falling back to the invites feature flag");
    }
    const fallback = await this.run("pause-invites", guildId, async (target) => {
      await target.disableInvites(untilMs !== null);
    });
    return { ...fallback, method: "feature", detail: `${reason.slice(0, 80)} (feature flag; does not expire automatically)` };
  }

  async getChannelSlowmode(guildId: string, channelId: string): Promise<number | null> {
    const channel = this.guildOf(guildId)?.channels.cache.get(channelId);
    if (!channel || !("rateLimitPerUser" in channel)) return null;
    return channel.rateLimitPerUser ?? 0;
  }

  async setChannelSlowmode(guildId: string, channelId: string, seconds: number, reason: string): Promise<ActionOutcome> {
    return this.run("set-slowmode", guildId, async (guild) => {
      const channel = guild.channels.cache.get(channelId);
      if (!channel || channel.isThread() || !("setRateLimitPerUser" in channel)) throw new Error("Channel does not support slowmode");
      await channel.setRateLimitPerUser(seconds, reason);
    });
  }

  async deleteMessages(guildId: string, channelId: string, messageIds: string[], reason: string): Promise<ActionOutcome> {
    return this.run("delete-messages", guildId, async (guild) => {
      const channel = guild.channels.cache.get(channelId);
      if (!channel || !channel.isTextBased()) throw new Error("Channel is not text based");
      const unique = [...new Set(messageIds)];
      if (unique.length === 1) {
        await channel.messages.delete(unique[0] as string);
        return;
      }
      for (let index = 0; index < unique.length; index += 100) {
        await channel.bulkDelete(unique.slice(index, index + 100), true);
      }
      this.logger.debug({ guildId, channelId, count: unique.length, reason }, "Messages deleted");
    });
  }

  async sendChannelMessage(guildId: string, channelId: string, message: OutgoingMessage): Promise<ActionOutcome> {
    return this.run("send-message", guildId, async (guild) => {
      const channel = guild.channels.cache.get(channelId) ?? (await guild.channels.fetch(channelId));
      if (!channel || !channel.isSendable()) throw new Error("Channel is not sendable");
      await channel.send({
        content: message.content,
        embeds: message.embeds,
        files: message.files?.map((file) => new AttachmentBuilder(file.data, { name: file.name })),
        allowedMentions: { parse: [], roles: message.mentionRoleIds ?? [], users: message.mentionUserIds ?? [] }
      });
    });
  }

  async canSendIn(guildId: string, channelId: string): Promise<{ ok: boolean; reason?: string }> {
    const guild = this.guildOf(guildId);
    if (!guild) return { ok: false, reason: "server unavailable" };
    const channel = guild.channels.cache.get(channelId);
    if (!channel) return { ok: false, reason: "channel not found" };
    if (!channel.isSendable()) return { ok: false, reason: "this channel does not accept messages" };
    const me = guild.members.me ?? (await guild.members.fetchMe().catch(() => null));
    if (!me) return { ok: false, reason: "Val Protection's membership could not be loaded" };
    const missing = channel.permissionsFor(me)?.missing([PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.EmbedLinks]) ?? ["ViewChannel"];
    return missing.length === 0 ? { ok: true } : { ok: false, reason: `missing ${missing.join(", ")} in this channel` };
  }

  async createRole(guildId: string, spec: RoleCreateSpec, reason: string): Promise<CreateOutcome> {
    let id: string | undefined;
    const outcome = await this.run("create-role", guildId, async (guild) => {
      const role = await guild.roles.create({
        name: spec.name,
        permissions: spec.permissions,
        colors: { primaryColor: spec.color },
        hoist: spec.hoist,
        mentionable: spec.mentionable,
        reason
      });
      id = role.id;
    });
    return id ? { ...outcome, id } : outcome;
  }

  async createChannel(guildId: string, spec: ChannelCreateSpec, reason: string): Promise<CreateOutcome> {
    let id: string | undefined;
    const outcome = await this.run("create-channel", guildId, async (guild) => {
      const channel = await guild.channels.create({
        name: spec.name,
        type: spec.type as ChannelType.GuildText,
        parent: spec.parentId ?? null,
        ...(TEXT_LIKE.has(spec.type) ? { topic: spec.topic ?? undefined, nsfw: spec.nsfw, rateLimitPerUser: spec.rateLimitPerUser } : {}),
        ...(VOICE_LIKE.has(spec.type) ? { bitrate: spec.bitrate ?? undefined, userLimit: spec.userLimit ?? undefined } : {}),
        permissionOverwrites: spec.overwrites.map((item) => ({
          id: item.id,
          type: item.type === "role" ? OverwriteType.Role : OverwriteType.Member,
          allow: item.allow,
          deny: item.deny
        })),
        reason
      });
      id = channel.id;
    });
    return id ? { ...outcome, id } : outcome;
  }

  private guildOf(guildId: string): Guild | null {
    const guild = this.client.guilds.cache.get(guildId);
    return guild?.available ? guild : null;
  }

  private async run(action: string, guildId: string, task: (guild: Guild) => Promise<void>): Promise<ActionOutcome> {
    const guild = this.guildOf(guildId);
    if (!guild) return { ok: false, action, error: "guild unavailable" };
    try {
      await task(guild);
      return { ok: true, action };
    } catch (error) {
      const code = discordErrorCode(error);
      this.logger.warn({ err: errorMessage(error), code, guildId, action }, "Discord action failed");
      return { ok: false, action, error: `${code ? `Discord error ${code}: ` : ""}${errorMessage(error)}` };
    }
  }

  private toRole(guild: Guild, role: Role): RoleInfo {
    return {
      id: role.id,
      name: role.name,
      permissions: role.permissions.bitfield,
      position: role.position,
      managed: role.managed,
      isEveryone: role.id === guild.id,
      botId: role.tags?.botId ?? null,
      color: role.colors.primaryColor,
      hoist: role.hoist,
      mentionable: role.mentionable
    };
  }

  private toMember(guild: Guild, member: GuildMember): MemberInfo {
    return {
      id: member.id,
      guildId: guild.id,
      username: member.user.username,
      isBot: member.user.bot,
      roleIds: [...member.roles.cache.keys()].filter((id) => id !== guild.id),
      permissions: member.permissions.bitfield,
      highestRolePosition: member.id === guild.ownerId ? Number.MAX_SAFE_INTEGER : member.roles.highest.position,
      isOwner: member.id === guild.ownerId,
      accountCreatedAt: member.user.createdTimestamp,
      joinedAt: member.joinedTimestamp,
      hasAvatar: member.user.avatar !== null,
      flaggedSpammer: member.user.flags?.has(UserFlags.Spammer) ?? false,
      communicationDisabledUntil: member.communicationDisabledUntilTimestamp
    };
  }

  private toChannel(channel: Exclude<GuildBasedChannel, { isThread(): true }>): ChannelInfo {
    const record = channel as unknown as Record<string, unknown>;
    const overwrites =
      "permissionOverwrites" in channel
        ? [...channel.permissionOverwrites.cache.values()].map((item) => ({
            id: item.id,
            type: item.type === OverwriteType.Role ? ("role" as const) : ("member" as const),
            allow: item.allow.bitfield,
            deny: item.deny.bitfield
          }))
        : [];
    return {
      id: channel.id,
      name: channel.name,
      type: channel.type,
      parentId: channel.parentId ?? null,
      position: "rawPosition" in channel ? channel.rawPosition : 0,
      topic: typeof record.topic === "string" ? record.topic : null,
      nsfw: record.nsfw === true,
      rateLimitPerUser: typeof record.rateLimitPerUser === "number" ? record.rateLimitPerUser : 0,
      bitrate: typeof record.bitrate === "number" ? record.bitrate : null,
      userLimit: typeof record.userLimit === "number" ? record.userLimit : null,
      overwrites
    };
  }
}
