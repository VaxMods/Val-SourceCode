export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export type Confidence = "none" | "low" | "medium" | "high";

export const CONFIDENCE_RANK: Record<Confidence, number> = { none: 0, low: 1, medium: 2, high: 3 };

export type ProtectionMode = "monitor" | "automatic";

export const ACTION_CATEGORIES = [
  "channelCreate",
  "channelDelete",
  "channelUpdate",
  "overwriteUpdate",
  "roleCreate",
  "roleDelete",
  "roleUpdate",
  "memberBan",
  "memberKick",
  "memberPrune",
  "memberRoleUpdate",
  "webhookCreate",
  "webhookUpdate",
  "webhookDelete",
  "botAdd",
  "integrationCreate",
  "integrationUpdate",
  "integrationDelete",
  "guildUpdate",
  "commandPermissionUpdate"
] as const;

export type ActionCategory = (typeof ACTION_CATEGORIES)[number];

export const WHITELIST_SCOPES = ["all", "roles", "channels", "moderation", "webhooks", "bots", "guild"] as const;

export type WhitelistScope = (typeof WHITELIST_SCOPES)[number];

export const CATEGORY_SCOPE: Record<ActionCategory, WhitelistScope> = {
  channelCreate: "channels",
  channelDelete: "channels",
  channelUpdate: "channels",
  overwriteUpdate: "channels",
  roleCreate: "roles",
  roleDelete: "roles",
  roleUpdate: "roles",
  memberRoleUpdate: "roles",
  memberBan: "moderation",
  memberKick: "moderation",
  memberPrune: "moderation",
  webhookCreate: "webhooks",
  webhookUpdate: "webhooks",
  webhookDelete: "webhooks",
  botAdd: "bots",
  integrationCreate: "bots",
  integrationUpdate: "bots",
  integrationDelete: "bots",
  commandPermissionUpdate: "bots",
  guildUpdate: "guild"
};

export interface ActionOutcome {
  ok: boolean;
  action: string;
  detail?: string;
  error?: string;
  skipped?: boolean;
}

export interface ActionRecord {
  action: string;
  target: string | null;
  rationale: string;
  outcome: ActionOutcome;
}

export function atLeastConfidence(value: Confidence, minimum: Confidence): boolean {
  return CONFIDENCE_RANK[value] >= CONFIDENCE_RANK[minimum];
}

export function atLeastSeverity(value: Severity, minimum: Severity): boolean {
  return SEVERITY_RANK[value] >= SEVERITY_RANK[minimum];
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}
