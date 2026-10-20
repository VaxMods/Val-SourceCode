import { ACTION_CATEGORIES } from "../core/types.js";
import { ValidationError } from "../core/errors.js";

export type SectionId = "general" | "access" | "raid" | "nuke" | "roles" | "bots" | "spam" | "honeypot" | "lockdown";

export type ListRole = "governance" | "trust" | "protective";

export type SettingKind =
  | { type: "boolean"; weakensWhenDisabled: boolean }
  | { type: "enum"; values: readonly string[]; order?: readonly string[]; weakensTo?: readonly string[] }
  | { type: "integer"; looser: "higher" | "lower" | "none" }
  | { type: "channel"; weakensWhenCleared: boolean; weakensWhenMoved: boolean }
  | { type: "role"; weakensWhenCleared: boolean }
  | { type: "users"; list: ListRole; botsOnly?: boolean; humansOnly?: boolean }
  | { type: "roles"; list: ListRole; noDangerousPermissions?: boolean }
  | { type: "channels"; list: ListRole }
  | { type: "domains"; list: ListRole }
  | { type: "patterns"; list: ListRole };

export interface SettingDefinition {
  path: string;
  label: string;
  section: SectionId;
  kind: SettingKind;
  ownerOnly: boolean;
}

const bool = (weakensWhenDisabled = true): SettingKind => ({ type: "boolean", weakensWhenDisabled });
const int = (looser: "higher" | "lower" | "none"): SettingKind => ({ type: "integer", looser });

const BASE: SettingDefinition[] = [
  { path: "mode", label: "Mode", section: "general", kind: { type: "enum", values: ["monitor", "automatic"], order: ["monitor", "automatic"] }, ownerOnly: false },
  { path: "alertChannelId", label: "Alert channel", section: "general", kind: { type: "channel", weakensWhenCleared: true, weakensWhenMoved: true }, ownerOnly: false },
  { path: "alertPingRoleId", label: "Role pinged on high alerts", section: "general", kind: { type: "role", weakensWhenCleared: false }, ownerOnly: false },
  { path: "weakeningChangesRequireOwner", label: "Owner approval for weakening changes", section: "general", kind: bool(), ownerOnly: true },

  { path: "securityAdminIds", label: "Security administrators", section: "access", kind: { type: "users", list: "governance", humansOnly: true }, ownerOnly: true },
  { path: "auditorRoleIds", label: "Auditor roles", section: "access", kind: { type: "roles", list: "governance" }, ownerOnly: true },
  { path: "staffRoleIds", label: "Staff roles", section: "access", kind: { type: "roles", list: "trust" }, ownerOnly: false },

  { path: "antiRaid.enabled", label: "Anti-raid", section: "raid", kind: bool(), ownerOnly: false },
  { path: "antiRaid.autoLockdown", label: "Automatic lockdown", section: "raid", kind: bool(), ownerOnly: false },
  { path: "antiRaid.actOnlyDuringRaid", label: "Measures only during raids", section: "raid", kind: bool(false), ownerOnly: false },
  { path: "antiRaid.quarantineRoleId", label: "Quarantine role", section: "raid", kind: { type: "role", weakensWhenCleared: true }, ownerOnly: false },
  { path: "antiRaid.suspectAction", label: "Measure for suspects", section: "raid", kind: { type: "enum", values: ["none", "quarantine", "timeout", "kick"], weakensTo: ["none"] }, ownerOnly: false },
  { path: "antiRaid.windowSeconds", label: "Surge window (seconds)", section: "raid", kind: int("lower"), ownerOnly: false },
  { path: "antiRaid.minJoinsForRaid", label: "Minimum joins for a raid", section: "raid", kind: int("higher"), ownerOnly: false },
  { path: "antiRaid.raidScoreThreshold", label: "Raid score threshold (0-100)", section: "raid", kind: int("higher"), ownerOnly: false },
  { path: "antiRaid.suspectScoreThreshold", label: "Suspect score threshold (10-100)", section: "raid", kind: int("higher"), ownerOnly: false },
  { path: "antiRaid.newAccountDays", label: "New account age (days)", section: "raid", kind: int("lower"), ownerOnly: false },
  { path: "antiRaid.slowWaveWindowMinutes", label: "Slow wave window (minutes)", section: "raid", kind: int("lower"), ownerOnly: false },
  { path: "antiRaid.slowWaveSuspectCount", label: "Suspects in a slow wave", section: "raid", kind: int("higher"), ownerOnly: false },
  { path: "antiRaid.timeoutMinutes", label: "Suspect timeout (minutes)", section: "raid", kind: int("none"), ownerOnly: false },
  { path: "antiRaid.kickMinScore", label: "Minimum score to kick (70-100)", section: "raid", kind: int("none"), ownerOnly: false },
  { path: "antiRaid.raidCooldownMinutes", label: "Raid cooldown (minutes)", section: "raid", kind: int("none"), ownerOnly: false },

  { path: "antiNuke.enabled", label: "Anti-nuke", section: "nuke", kind: bool(), ownerOnly: false },
  { path: "antiNuke.response", label: "Response", section: "nuke", kind: { type: "enum", values: ["alert", "contain"], order: ["alert", "contain"] }, ownerOnly: false },
  { path: "antiNuke.minConfidenceToContain", label: "Minimum confidence to contain", section: "nuke", kind: { type: "enum", values: ["high", "medium"], order: ["high", "medium"] }, ownerOnly: false },
  { path: "antiNuke.containBotsByKick", label: "Kick destructive bots", section: "nuke", kind: bool(), ownerOnly: false },
  { path: "antiNuke.autoLockdownOnSeverity", label: "Automatic lockdown from", section: "nuke", kind: { type: "enum", values: ["never", "high", "critical"], order: ["never", "critical", "high"] }, ownerOnly: false },

  { path: "roleProtection.enabled", label: "Role protection", section: "roles", kind: bool(), ownerOnly: false },
  { path: "roleProtection.treatDangerousRolesAsProtected", label: "Protect every dangerous role", section: "roles", kind: bool(), ownerOnly: false },
  { path: "roleProtection.revokeFromRecipient", label: "Revoke unauthorized grants", section: "roles", kind: bool(), ownerOnly: false },
  { path: "roleProtection.revertUnauthorizedPermissionChanges", label: "Revert permission escalations", section: "roles", kind: bool(), ownerOnly: false },
  { path: "roleProtection.granterResponse", label: "Restrict the granter", section: "roles", kind: { type: "enum", values: ["none", "strip-role-management"], order: ["none", "strip-role-management"] }, ownerOnly: false },
  { path: "roleProtection.authorizedGranterIds", label: "Allowed to grant every protected role", section: "roles", kind: { type: "users", list: "trust" }, ownerOnly: false },

  { path: "bots.approvedBotIds", label: "Approved bots", section: "bots", kind: { type: "users", list: "trust", botsOnly: true }, ownerOnly: false },
  { path: "bots.authorizedAdderIds", label: "Allowed to add bots", section: "bots", kind: { type: "users", list: "trust", humansOnly: true }, ownerOnly: false },
  { path: "bots.unapprovedAction", label: "Unapproved bots", section: "bots", kind: { type: "enum", values: ["alert", "kick"], order: ["alert", "kick"] }, ownerOnly: false },
  { path: "bots.kickOnlyWhenAdderUnauthorized", label: "Kick only if the adder is unauthorized", section: "bots", kind: bool(false), ownerOnly: false },
  { path: "integrations.authorizedManagerIds", label: "Allowed to manage webhooks and integrations", section: "bots", kind: { type: "users", list: "trust" }, ownerOnly: false },
  { path: "integrations.unauthorizedWebhookAction", label: "Unauthorized webhooks", section: "bots", kind: { type: "enum", values: ["alert", "delete"], order: ["alert", "delete"] }, ownerOnly: false },

  { path: "antiSpam.enabled", label: "Anti-spam", section: "spam", kind: bool(), ownerOnly: false },
  { path: "antiSpam.exemptRoleIds", label: "Exempt roles", section: "spam", kind: { type: "roles", list: "trust" }, ownerOnly: false },
  { path: "antiSpam.exemptChannelIds", label: "Exempt channels", section: "spam", kind: { type: "channels", list: "trust" }, ownerOnly: false },
  { path: "antiSpam.burst.maxMessages", label: "Burst: maximum messages", section: "spam", kind: int("higher"), ownerOnly: false },
  { path: "antiSpam.burst.windowSeconds", label: "Burst: window (seconds)", section: "spam", kind: int("lower"), ownerOnly: false },
  { path: "antiSpam.duplicates.max", label: "Identical messages allowed", section: "spam", kind: int("higher"), ownerOnly: false },
  { path: "antiSpam.maxMentions", label: "Mentions per message", section: "spam", kind: int("higher"), ownerOnly: false },
  { path: "antiSpam.timeoutMinutes", label: "Spam timeout (minutes)", section: "spam", kind: int("none"), ownerOnly: false },
  { path: "antiSpam.links.blockedDomains", label: "Blocked domains", section: "spam", kind: { type: "domains", list: "protective" }, ownerOnly: false },
  { path: "antiSpam.links.allowedDomains", label: "Allowed domains", section: "spam", kind: { type: "domains", list: "trust" }, ownerOnly: false },
  { path: "antiSpam.links.flagInvites", label: "Invites", section: "spam", kind: bool(), ownerOnly: false },
  { path: "antiSpam.links.flagShorteners", label: "Shorteners", section: "spam", kind: bool(), ownerOnly: false },
  { path: "antiSpam.links.flagLookalikes", label: "Look-alikes", section: "spam", kind: bool(), ownerOnly: false },
  { path: "antiSpam.links.flagIpHosts", label: "IP links", section: "spam", kind: bool(), ownerOnly: false },
  { path: "antiSpam.floodSlowmode.enabled", label: "Flood slowmode", section: "spam", kind: bool(), ownerOnly: false },

  { path: "honeypot.enabled", label: "Honeypot", section: "honeypot", kind: bool(), ownerOnly: false },
  { path: "honeypot.decoyRoleIds", label: "Decoy roles", section: "honeypot", kind: { type: "roles", list: "protective", noDangerousPermissions: true }, ownerOnly: false },
  { path: "honeypot.decoyChannelIds", label: "Decoy channels", section: "honeypot", kind: { type: "channels", list: "protective" }, ownerOnly: false },
  { path: "honeypot.escalationAction", label: "Escalation", section: "honeypot", kind: { type: "enum", values: ["alert", "timeout"], order: ["alert", "timeout"] }, ownerOnly: false },
  { path: "honeypot.forbiddenCommandPatterns", label: "Forbidden command traps", section: "honeypot", kind: { type: "patterns", list: "protective" }, ownerOnly: false },

  { path: "lockdown.verificationLevel", label: "Lockdown verification level", section: "lockdown", kind: { type: "enum", values: ["Medium", "High", "VeryHigh"], order: ["Medium", "High", "VeryHigh"] }, ownerOnly: false },
  { path: "lockdown.raiseVerificationLevel", label: "Raise verification", section: "lockdown", kind: bool(), ownerOnly: false },
  { path: "lockdown.pauseInvites", label: "Pause invites", section: "lockdown", kind: bool(), ownerOnly: false },
  { path: "lockdown.quarantineNewMembers", label: "Quarantine newcomers", section: "lockdown", kind: bool(), ownerOnly: false },
  { path: "lockdown.restrictProtectedRoleGrants", label: "Restrict sensitive grants", section: "lockdown", kind: bool(), ownerOnly: false },
  { path: "lockdown.suspendNonEssential", label: "Mute warnings", section: "lockdown", kind: bool(false), ownerOnly: false },
  { path: "lockdown.maxDurationMinutes", label: "Maximum lockdown (minutes)", section: "lockdown", kind: int("none"), ownerOnly: false },
  { path: "logging.retentionDays", label: "Evidence retention (days)", section: "lockdown", kind: int("lower"), ownerOnly: false },
  { path: "backups.enabled", label: "Snapshots", section: "lockdown", kind: bool(), ownerOnly: false },
  { path: "backups.intervalMinutes", label: "Snapshot interval (minutes)", section: "lockdown", kind: int("none"), ownerOnly: false },
  { path: "backups.keep", label: "Snapshots kept", section: "lockdown", kind: int("none"), ownerOnly: false }
];

const NUKE: SettingDefinition[] = ACTION_CATEGORIES.flatMap((category) => [
  { path: `antiNuke.thresholds.${category}.limit`, label: `${category}: maximum actions`, section: "nuke" as const, kind: int("higher"), ownerOnly: false },
  { path: `antiNuke.thresholds.${category}.windowSeconds`, label: `${category}: window (seconds)`, section: "nuke" as const, kind: int("lower"), ownerOnly: false }
]);

export const SETTINGS: ReadonlyMap<string, SettingDefinition> = new Map([...BASE, ...NUKE].map((definition) => [definition.path, definition]));

export function getSetting(path: string): SettingDefinition {
  const definition = SETTINGS.get(path);
  if (!definition) throw new ValidationError(`${path} cannot be changed from Discord`);
  return definition;
}

export function isScalar(definition: SettingDefinition): boolean {
  return ["boolean", "enum", "integer", "channel", "role"].includes(definition.kind.type);
}

const SNOWFLAKE = /^\d{17,20}$/;

function asIdList(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) throw new ValidationError(`${path} expects a list`);
  const ids = [...new Set(value.map((item) => String(item).trim()))];
  if (ids.some((id) => !SNOWFLAKE.test(id))) throw new ValidationError(`${path} contains an invalid Discord ID`);
  if (ids.length > 100) throw new ValidationError(`${path} accepts at most 100 entries`);
  return ids;
}

function asTextList(value: unknown, path: string, max: number, normalize: (item: string) => string = (item) => item): string[] {
  const items = Array.isArray(value) ? value.map((item) => String(item)) : String(value ?? "").split(/[\r\n,]+/);
  const cleaned = [...new Set(items.map((item) => normalize(item.trim())).filter((item) => item.length > 0))];
  if (cleaned.length > max) throw new ValidationError(`${path} accepts at most ${max} entries`);
  return cleaned;
}

export function coerceSettingValue(definition: SettingDefinition, raw: unknown): unknown {
  const { kind, path } = definition;
  switch (kind.type) {
    case "boolean":
      if (typeof raw === "boolean") return raw;
      if (typeof raw === "string" && ["true", "on", "yes", "1"].includes(raw.trim().toLowerCase())) return true;
      if (typeof raw === "string" && ["false", "off", "no", "0"].includes(raw.trim().toLowerCase())) return false;
      throw new ValidationError(`${definition.label} expects on or off`);
    case "enum": {
      const value = String(raw).trim();
      if (!kind.values.includes(value)) throw new ValidationError(`${definition.label} expects one of: ${kind.values.join(", ")}`);
      return value;
    }
    case "integer": {
      if (typeof raw === "number" && Number.isSafeInteger(raw)) return raw;
      const text = String(raw ?? "").trim();
      if (!/^\d{1,9}$/.test(text)) throw new ValidationError(`${definition.label} expects a whole number`);
      return Number.parseInt(text, 10);
    }
    case "channel":
    case "role": {
      if (raw === null || raw === undefined) return null;
      const text = String(raw).trim();
      if (["", "none", "null", "off"].includes(text.toLowerCase())) return null;
      if (!SNOWFLAKE.test(text)) throw new ValidationError(`${definition.label} expects a Discord ID or "none"`);
      return text;
    }
    case "users":
    case "roles":
    case "channels":
      return asIdList(raw, path);
    case "domains":
      return asTextList(raw, path, 1000, (item) => item.toLowerCase());
    case "patterns":
      return asTextList(raw, path, 50);
  }
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function listDelta(previous: unknown, next: unknown): { added: string[]; removed: string[] } {
  const before = new Set(Array.isArray(previous) ? previous.map(String) : []);
  const after = new Set(Array.isArray(next) ? next.map(String) : []);
  return { added: [...after].filter((item) => !before.has(item)), removed: [...before].filter((item) => !after.has(item)) };
}

export function isWeakening(definition: SettingDefinition, previous: unknown, next: unknown): boolean {
  if (sameValue(previous, next)) return false;
  const { kind } = definition;
  switch (kind.type) {
    case "boolean":
      return kind.weakensWhenDisabled && previous === true && next === false;
    case "enum":
      if (kind.weakensTo?.includes(String(next))) return true;
      if (kind.order) return kind.order.indexOf(String(next)) < kind.order.indexOf(String(previous));
      return false;
    case "integer":
      if (typeof previous !== "number" || typeof next !== "number") return false;
      return (kind.looser === "higher" && next > previous) || (kind.looser === "lower" && next < previous);
    case "channel":
      return (kind.weakensWhenCleared && previous !== null && next === null) || (kind.weakensWhenMoved && previous !== null && next !== null);
    case "role":
      return kind.weakensWhenCleared && previous !== null && next === null;
    case "users":
    case "roles":
    case "channels":
    case "domains":
    case "patterns": {
      const { added, removed } = listDelta(previous, next);
      if (kind.list === "trust") return added.length > 0;
      if (kind.list === "protective") return removed.length > 0;
      return added.length > 0 || removed.length > 0;
    }
  }
}

export function describeValue(definition: SettingDefinition, value: unknown): string {
  const { kind } = definition;
  if (value === null || value === undefined) return "none";
  switch (kind.type) {
    case "boolean":
      return value ? "on" : "off";
    case "channel":
      return `<#${String(value)}>`;
    case "role":
      return `<@&${String(value)}>`;
    case "users":
      return Array.isArray(value) && value.length > 0 ? value.map((id) => `<@${String(id)}>`).join(", ") : "none";
    case "roles":
      return Array.isArray(value) && value.length > 0 ? value.map((id) => `<@&${String(id)}>`).join(", ") : "none";
    case "channels":
      return Array.isArray(value) && value.length > 0 ? value.map((id) => `<#${String(id)}>`).join(", ") : "none";
    case "domains":
    case "patterns":
      return Array.isArray(value) && value.length > 0 ? value.map((item) => `\`${String(item).replace(/`/g, "'")}\``).join(", ") : "none";
    default:
      return String(value);
  }
}
