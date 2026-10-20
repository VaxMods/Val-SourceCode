import { AuditLogEvent } from "discord.js";
import type { ActionCategory } from "../core/types.js";

export interface AuditChange {
  key: string;
  old: unknown;
  new: unknown;
}

export interface AuditEvent {
  id: string;
  guildId: string;
  actionType: number;
  actionName: string;
  category: ActionCategory | null;
  executorId: string | null;
  targetId: string | null;
  reason: string | null;
  changes: AuditChange[];
  extra: Record<string, unknown>;
  createdAt: number;
  source: "gateway" | "fetch";
}

export interface AuditEntryLike {
  id: string;
  action: number;
  executorId: string | null;
  targetId: string | null;
  reason: string | null;
  changes: ReadonlyArray<{ key: string; old?: unknown; new?: unknown }>;
  extra: unknown;
  createdTimestamp: number;
}

const CATEGORY_BY_ACTION = new Map<number, ActionCategory>([
  [AuditLogEvent.GuildUpdate, "guildUpdate"],
  [AuditLogEvent.ChannelCreate, "channelCreate"],
  [AuditLogEvent.ChannelUpdate, "channelUpdate"],
  [AuditLogEvent.ChannelDelete, "channelDelete"],
  [AuditLogEvent.ChannelOverwriteCreate, "overwriteUpdate"],
  [AuditLogEvent.ChannelOverwriteUpdate, "overwriteUpdate"],
  [AuditLogEvent.ChannelOverwriteDelete, "overwriteUpdate"],
  [AuditLogEvent.MemberKick, "memberKick"],
  [AuditLogEvent.MemberPrune, "memberPrune"],
  [AuditLogEvent.MemberBanAdd, "memberBan"],
  [AuditLogEvent.MemberRoleUpdate, "memberRoleUpdate"],
  [AuditLogEvent.BotAdd, "botAdd"],
  [AuditLogEvent.RoleCreate, "roleCreate"],
  [AuditLogEvent.RoleUpdate, "roleUpdate"],
  [AuditLogEvent.RoleDelete, "roleDelete"],
  [AuditLogEvent.WebhookCreate, "webhookCreate"],
  [AuditLogEvent.WebhookUpdate, "webhookUpdate"],
  [AuditLogEvent.WebhookDelete, "webhookDelete"],
  [AuditLogEvent.IntegrationCreate, "integrationCreate"],
  [AuditLogEvent.IntegrationUpdate, "integrationUpdate"],
  [AuditLogEvent.IntegrationDelete, "integrationDelete"],
  [AuditLogEvent.ApplicationCommandPermissionUpdate, "commandPermissionUpdate"]
]);

export function categoryOf(actionType: number): ActionCategory | null {
  return CATEGORY_BY_ACTION.get(actionType) ?? null;
}

function plainExtra(extra: unknown): Record<string, unknown> {
  if (extra === null || typeof extra !== "object") return {};
  const source = extra as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  const channel = source.channel;
  if (channel && typeof channel === "object" && "id" in channel) output.channelId = String((channel as { id: unknown }).id);
  for (const key of ["count", "removed", "days", "applicationId", "messageId", "type"]) {
    const value = source[key];
    if (typeof value === "string" || typeof value === "number") output[key] = value;
  }
  if (typeof source.id === "string") output.overwriteId = source.id;
  return output;
}

export function normalizeAuditEntry(entry: AuditEntryLike, guildId: string, source: "gateway" | "fetch"): AuditEvent {
  return {
    id: entry.id,
    guildId,
    actionType: entry.action,
    actionName: (AuditLogEvent as unknown as Record<number, string>)[entry.action] ?? `Action${entry.action}`,
    category: categoryOf(entry.action),
    executorId: entry.executorId,
    targetId: entry.targetId,
    reason: entry.reason ? entry.reason.slice(0, 512) : null,
    changes: entry.changes.map((change) => ({ key: change.key, old: change.old ?? null, new: change.new ?? null })),
    extra: plainExtra(entry.extra),
    createdAt: entry.createdTimestamp,
    source
  };
}

export function findChange(event: AuditEvent, key: string): AuditChange | undefined {
  return event.changes.find((change) => change.key === key);
}

export function rolesFromChange(event: AuditEvent, key: "$add" | "$remove"): Array<{ id: string; name: string }> {
  const change = findChange(event, key);
  if (!change || !Array.isArray(change.new)) return [];
  return change.new
    .filter((item): item is { id: string; name?: string } => typeof item === "object" && item !== null && typeof (item as { id?: unknown }).id === "string")
    .map((item) => ({ id: item.id, name: typeof item.name === "string" ? item.name : item.id }));
}

export function auditConfidence(event: AuditEvent): "high" | "medium" | "none" {
  if (!event.executorId) return "none";
  return event.source === "gateway" ? "high" : "medium";
}
