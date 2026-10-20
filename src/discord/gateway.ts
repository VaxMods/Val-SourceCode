import type { APIEmbed } from "discord.js";
import type { ActionOutcome } from "../core/types.js";
import type { AuditEvent } from "./auditEvent.js";

export interface GuildInfo {
  id: string;
  name: string;
  ownerId: string;
  botUserId: string;
  botHighestRolePosition: number;
  botPermissions: bigint;
  verificationLevel: number;
  mfaLevel: number;
  explicitContentFilter: number;
  invitesPaused: boolean;
  memberCount: number;
}

export interface RoleInfo {
  id: string;
  name: string;
  permissions: bigint;
  position: number;
  managed: boolean;
  isEveryone: boolean;
  botId: string | null;
  color: number;
  hoist: boolean;
  mentionable: boolean;
}

export interface MemberInfo {
  id: string;
  guildId: string;
  username: string;
  isBot: boolean;
  roleIds: string[];
  permissions: bigint;
  highestRolePosition: number;
  isOwner: boolean;
  accountCreatedAt: number;
  joinedAt: number | null;
  hasAvatar: boolean;
  flaggedSpammer: boolean;
  communicationDisabledUntil: number | null;
}

export interface OverwriteInfo {
  id: string;
  type: "role" | "member";
  allow: bigint;
  deny: bigint;
}

export interface ChannelInfo {
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
  overwrites: OverwriteInfo[];
}

export interface OutgoingFile {
  name: string;
  data: Buffer;
}

export interface OutgoingMessage {
  content?: string;
  embeds: APIEmbed[];
  mentionRoleIds?: string[];
  mentionUserIds?: string[];
  files?: OutgoingFile[];
}

export interface RoleCreateSpec {
  name: string;
  permissions: bigint;
  color: number;
  hoist: boolean;
  mentionable: boolean;
}

export interface ChannelCreateSpec {
  name: string;
  type: number;
  parentId: string | null;
  topic: string | null;
  nsfw: boolean;
  rateLimitPerUser: number;
  bitrate: number | null;
  userLimit: number | null;
  overwrites: OverwriteInfo[];
}

export type CreateOutcome = ActionOutcome & { id?: string };

export type InvitePauseOutcome = ActionOutcome & { method?: "incident-actions" | "feature" };

export interface DiscordGateway {
  getGuild(guildId: string): Promise<GuildInfo | null>;
  getRole(guildId: string, roleId: string): Promise<RoleInfo | null>;
  listRoles(guildId: string): Promise<RoleInfo[]>;
  getMember(guildId: string, userId: string): Promise<MemberInfo | null>;
  listMembers(guildId: string, limit: number): Promise<MemberInfo[] | null>;
  listChannels(guildId: string): Promise<ChannelInfo[]>;
  findAuditEvents(guildId: string, actionType: number, limit: number): Promise<AuditEvent[]>;
  addMemberRole(guildId: string, userId: string, roleId: string, reason: string): Promise<ActionOutcome>;
  removeMemberRoles(guildId: string, userId: string, roleIds: string[], reason: string): Promise<ActionOutcome>;
  setRolePermissions(guildId: string, roleId: string, permissions: bigint, reason: string): Promise<ActionOutcome>;
  kickMember(guildId: string, userId: string, reason: string): Promise<ActionOutcome>;
  timeoutMember(guildId: string, userId: string, durationMs: number, reason: string): Promise<ActionOutcome>;
  deleteWebhook(guildId: string, webhookId: string, reason: string): Promise<ActionOutcome>;
  setVerificationLevel(guildId: string, level: number, reason: string): Promise<ActionOutcome>;
  pauseInvites(guildId: string, untilMs: number | null, reason: string): Promise<InvitePauseOutcome>;
  getChannelSlowmode(guildId: string, channelId: string): Promise<number | null>;
  setChannelSlowmode(guildId: string, channelId: string, seconds: number, reason: string): Promise<ActionOutcome>;
  deleteMessages(guildId: string, channelId: string, messageIds: string[], reason: string): Promise<ActionOutcome>;
  sendChannelMessage(guildId: string, channelId: string, message: OutgoingMessage): Promise<ActionOutcome>;
  canSendIn(guildId: string, channelId: string): Promise<{ ok: boolean; reason?: string }>;
  createRole(guildId: string, spec: RoleCreateSpec, reason: string): Promise<CreateOutcome>;
  createChannel(guildId: string, spec: ChannelCreateSpec, reason: string): Promise<CreateOutcome>;
}
