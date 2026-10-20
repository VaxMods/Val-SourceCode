import { AuditLogEvent, ChannelType } from "discord.js";
import type { ActionOutcome } from "../core/types.js";
import type { AuditEvent } from "../discord/auditEvent.js";
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
} from "../discord/gateway.js";
import { ADMINISTRATOR } from "../discord/permissions.js";

export interface GatewayCall {
  method: string;
  args: unknown[];
}

export interface SentMessage {
  channelId: string;
  message: OutgoingMessage;
}

export interface GuildSeed {
  guildId: string;
  name: string;
  ownerId: string;
  botUserId: string;
  verificationLevel?: number;
  mfaLevel?: number;
  explicitContentFilter?: number;
}

const SIMULATED_FAILURE = "Discord API unavailable (simulated)";

export class InMemoryGateway implements DiscordGateway {
  readonly roles = new Map<string, RoleInfo>();
  readonly members = new Map<string, MemberInfo>();
  readonly channels = new Map<string, ChannelInfo>();
  readonly webhooks = new Set<string>();
  readonly auditLog: AuditEvent[] = [];
  readonly calls: GatewayCall[] = [];
  readonly sent: SentMessage[] = [];
  readonly deletedMessages: string[] = [];
  private readonly failing = new Set<string>();
  private nextId = 1n;
  private info: Omit<GuildInfo, "botHighestRolePosition" | "botPermissions" | "memberCount">;

  constructor(
    seed: GuildSeed,
    private readonly now: () => number = Date.now
  ) {
    this.info = {
      id: seed.guildId,
      name: seed.name,
      ownerId: seed.ownerId,
      botUserId: seed.botUserId,
      verificationLevel: seed.verificationLevel ?? 1,
      mfaLevel: seed.mfaLevel ?? 1,
      explicitContentFilter: seed.explicitContentFilter ?? 2,
      invitesPaused: false
    };
    this.roles.set(seed.guildId, {
      id: seed.guildId,
      name: "@everyone",
      permissions: 0n,
      position: 0,
      managed: false,
      isEveryone: true,
      botId: null,
      color: 0,
      hoist: false,
      mentionable: false
    });
  }

  newId(): string {
    const id = (900000000000000000n + this.nextId).toString();
    this.nextId += 1n;
    return id;
  }

  fail(method: string | "all"): void {
    this.failing.add(method);
  }

  heal(method?: string): void {
    if (method) this.failing.delete(method);
    else this.failing.clear();
  }

  callsTo(method: string): GatewayCall[] {
    return this.calls.filter((call) => call.method === method);
  }

  get guildState(): typeof this.info {
    return this.info;
  }

  addRole(partial: Partial<RoleInfo> & { name: string }): RoleInfo {
    const role: RoleInfo = {
      id: partial.id ?? this.newId(),
      name: partial.name,
      permissions: partial.permissions ?? 0n,
      position: partial.position ?? this.roles.size,
      managed: partial.managed ?? false,
      isEveryone: false,
      botId: partial.botId ?? null,
      color: partial.color ?? 0,
      hoist: partial.hoist ?? false,
      mentionable: partial.mentionable ?? false
    };
    this.roles.set(role.id, role);
    this.recomputeAll();
    return role;
  }

  addMember(partial: Partial<MemberInfo> & { id?: string; username: string }): MemberInfo {
    const id = partial.id ?? this.newId();
    const member: MemberInfo = {
      id,
      guildId: this.info.id,
      username: partial.username,
      isBot: partial.isBot ?? false,
      roleIds: partial.roleIds ?? [],
      permissions: 0n,
      highestRolePosition: 0,
      isOwner: id === this.info.ownerId,
      accountCreatedAt: partial.accountCreatedAt ?? Date.UTC(2020, 0, 1),
      joinedAt: partial.joinedAt ?? Date.UTC(2021, 0, 1),
      hasAvatar: partial.hasAvatar ?? true,
      flaggedSpammer: partial.flaggedSpammer ?? false,
      communicationDisabledUntil: null
    };
    this.members.set(id, member);
    this.recompute(member);
    return member;
  }

  addChannel(partial: Partial<ChannelInfo> & { name: string }): ChannelInfo {
    const channel: ChannelInfo = {
      id: partial.id ?? this.newId(),
      name: partial.name,
      type: partial.type ?? ChannelType.GuildText,
      parentId: partial.parentId ?? null,
      position: partial.position ?? this.channels.size,
      topic: partial.topic ?? null,
      nsfw: partial.nsfw ?? false,
      rateLimitPerUser: partial.rateLimitPerUser ?? 0,
      bitrate: partial.bitrate ?? null,
      userLimit: partial.userLimit ?? null,
      overwrites: partial.overwrites ?? []
    };
    this.channels.set(channel.id, channel);
    return channel;
  }

  setRolePermissionsDirect(roleId: string, permissions: bigint): void {
    const role = this.roles.get(roleId);
    if (role) role.permissions = permissions;
    this.recomputeAll();
  }

  grantRoleDirect(memberId: string, roleId: string): void {
    const member = this.members.get(memberId);
    if (member && !member.roleIds.includes(roleId)) member.roleIds.push(roleId);
    if (member) this.recompute(member);
  }

  recordAudit(event: Omit<AuditEvent, "guildId" | "source" | "actionName" | "category" | "extra" | "changes" | "reason"> & Partial<AuditEvent>): AuditEvent {
    const full: AuditEvent = {
      guildId: this.info.id,
      source: "gateway",
      actionName: (AuditLogEvent as unknown as Record<number, string>)[event.actionType] ?? `Action${event.actionType}`,
      category: null,
      extra: {},
      changes: [],
      reason: null,
      ...event
    };
    this.auditLog.push(full);
    return full;
  }

  async getGuild(guildId: string): Promise<GuildInfo | null> {
    if (this.blocked("getGuild") || guildId !== this.info.id) return null;
    const bot = this.members.get(this.info.botUserId);
    return {
      ...this.info,
      botHighestRolePosition: bot?.highestRolePosition ?? 0,
      botPermissions: bot?.permissions ?? 0n,
      memberCount: this.members.size
    };
  }

  async getRole(guildId: string, roleId: string): Promise<RoleInfo | null> {
    if (this.blocked("getRole") || guildId !== this.info.id) return null;
    const role = this.roles.get(roleId);
    return role ? { ...role } : null;
  }

  async listRoles(guildId: string): Promise<RoleInfo[]> {
    if (this.blocked("listRoles") || guildId !== this.info.id) return [];
    return [...this.roles.values()].map((role) => ({ ...role }));
  }

  async getMember(guildId: string, userId: string): Promise<MemberInfo | null> {
    if (this.blocked("getMember") || guildId !== this.info.id) return null;
    const member = this.members.get(userId);
    return member ? { ...member, roleIds: [...member.roleIds] } : null;
  }

  async listMembers(guildId: string, limit: number): Promise<MemberInfo[] | null> {
    if (this.blocked("listMembers") || guildId !== this.info.id) return null;
    return [...this.members.values()].slice(0, limit).map((member) => ({ ...member, roleIds: [...member.roleIds] }));
  }

  async listChannels(guildId: string): Promise<ChannelInfo[]> {
    if (this.blocked("listChannels") || guildId !== this.info.id) return [];
    return [...this.channels.values()].map((channel) => ({ ...channel, overwrites: channel.overwrites.map((item) => ({ ...item })) }));
  }

  async findAuditEvents(guildId: string, actionType: number, limit: number): Promise<AuditEvent[]> {
    if (this.blocked("findAuditEvents") || guildId !== this.info.id) return [];
    return this.auditLog
      .filter((event) => event.actionType === actionType)
      .slice(-limit)
      .reverse()
      .map((event) => ({ ...event, source: "fetch" as const }));
  }

  async addMemberRole(guildId: string, userId: string, roleId: string, reason: string): Promise<ActionOutcome> {
    return this.mutate("addMemberRole", [guildId, userId, roleId, reason], () => {
      const member = this.members.get(userId);
      if (!member) return "Unknown Member";
      if (!member.roleIds.includes(roleId)) member.roleIds.push(roleId);
      this.recompute(member);
      return null;
    });
  }

  async removeMemberRoles(guildId: string, userId: string, roleIds: string[], reason: string): Promise<ActionOutcome> {
    return this.mutate("removeMemberRoles", [guildId, userId, roleIds, reason], () => {
      const member = this.members.get(userId);
      if (!member) return "Unknown Member";
      member.roleIds = member.roleIds.filter((id) => !roleIds.includes(id));
      this.recompute(member);
      return null;
    });
  }

  async setRolePermissions(guildId: string, roleId: string, permissions: bigint, reason: string): Promise<ActionOutcome> {
    return this.mutate("setRolePermissions", [guildId, roleId, permissions, reason], () => {
      const role = this.roles.get(roleId);
      if (!role) return "Unknown Role";
      role.permissions = permissions;
      this.recomputeAll();
      return null;
    });
  }

  async kickMember(guildId: string, userId: string, reason: string): Promise<ActionOutcome> {
    return this.mutate("kickMember", [guildId, userId, reason], () => (this.members.delete(userId) ? null : "Unknown Member"));
  }

  async timeoutMember(guildId: string, userId: string, durationMs: number, reason: string): Promise<ActionOutcome> {
    return this.mutate("timeoutMember", [guildId, userId, durationMs, reason], () => {
      const member = this.members.get(userId);
      if (!member) return "Unknown Member";
      member.communicationDisabledUntil = this.now() + durationMs;
      return null;
    });
  }

  async deleteWebhook(guildId: string, webhookId: string, reason: string): Promise<ActionOutcome> {
    return this.mutate("deleteWebhook", [guildId, webhookId, reason], () => (this.webhooks.delete(webhookId) ? null : "Unknown Webhook"));
  }

  async setVerificationLevel(guildId: string, level: number, reason: string): Promise<ActionOutcome> {
    return this.mutate("setVerificationLevel", [guildId, level, reason], () => {
      this.info.verificationLevel = level;
      return null;
    });
  }

  async pauseInvites(guildId: string, untilMs: number | null, reason: string): Promise<InvitePauseOutcome> {
    const outcome = await this.mutate("pauseInvites", [guildId, untilMs, reason], () => {
      this.info.invitesPaused = untilMs !== null;
      return null;
    });
    return { ...outcome, method: "incident-actions" };
  }

  async getChannelSlowmode(guildId: string, channelId: string): Promise<number | null> {
    if (this.blocked("getChannelSlowmode") || guildId !== this.info.id) return null;
    return this.channels.get(channelId)?.rateLimitPerUser ?? null;
  }

  async setChannelSlowmode(guildId: string, channelId: string, seconds: number, reason: string): Promise<ActionOutcome> {
    return this.mutate("setChannelSlowmode", [guildId, channelId, seconds, reason], () => {
      const channel = this.channels.get(channelId);
      if (!channel) return "Unknown Channel";
      channel.rateLimitPerUser = seconds;
      return null;
    });
  }

  async deleteMessages(guildId: string, channelId: string, messageIds: string[], reason: string): Promise<ActionOutcome> {
    return this.mutate("deleteMessages", [guildId, channelId, messageIds, reason], () => {
      this.deletedMessages.push(...messageIds);
      return null;
    });
  }

  async sendChannelMessage(guildId: string, channelId: string, message: OutgoingMessage): Promise<ActionOutcome> {
    return this.mutate("sendChannelMessage", [guildId, channelId], () => {
      if (!this.channels.has(channelId)) return "Unknown Channel";
      this.sent.push({ channelId, message });
      return null;
    });
  }

  async canSendIn(guildId: string, channelId: string): Promise<{ ok: boolean; reason?: string }> {
    if (this.blocked("canSendIn") || guildId !== this.info.id) return { ok: false, reason: "missing SendMessages in this channel" };
    const channel = this.channels.get(channelId);
    if (!channel) return { ok: false, reason: "channel not found" };
    if (channel.type === ChannelType.GuildCategory) return { ok: false, reason: "this channel does not accept messages" };
    return { ok: true };
  }

  async createRole(guildId: string, spec: RoleCreateSpec, reason: string): Promise<CreateOutcome> {
    let id: string | undefined;
    const outcome = await this.mutate("createRole", [guildId, spec, reason], () => {
      id = this.addRole({ name: spec.name, permissions: spec.permissions, color: spec.color, hoist: spec.hoist, mentionable: spec.mentionable, position: 1 }).id;
      return null;
    });
    return id ? { ...outcome, id } : outcome;
  }

  async createChannel(guildId: string, spec: ChannelCreateSpec, reason: string): Promise<CreateOutcome> {
    let id: string | undefined;
    const outcome = await this.mutate("createChannel", [guildId, spec, reason], () => {
      id = this.addChannel({ ...spec }).id;
      return null;
    });
    return id ? { ...outcome, id } : outcome;
  }

  private blocked(method: string): boolean {
    return this.failing.has("all") || this.failing.has(method);
  }

  private async mutate(method: string, args: unknown[], apply: () => string | null): Promise<ActionOutcome> {
    this.calls.push({ method, args });
    if (this.blocked(method)) return { ok: false, action: method, error: SIMULATED_FAILURE };
    const error = apply();
    return error ? { ok: false, action: method, error } : { ok: true, action: method };
  }

  private recomputeAll(): void {
    for (const member of this.members.values()) this.recompute(member);
  }

  private recompute(member: MemberInfo): void {
    const everyone = this.roles.get(this.info.id);
    let permissions = everyone?.permissions ?? 0n;
    let highest = 0;
    for (const roleId of member.roleIds) {
      const role = this.roles.get(roleId);
      if (!role) continue;
      permissions |= role.permissions;
      highest = Math.max(highest, role.position);
    }
    if (member.isOwner) permissions = (1n << 53n) - 1n | ADMINISTRATOR;
    member.permissions = permissions;
    member.highestRolePosition = member.isOwner ? Number.MAX_SAFE_INTEGER : highest;
  }
}
