import { PermissionFlagsBits } from "discord.js";
import type { ActionCategory } from "../core/types.js";

export type PermissionName = Exclude<keyof typeof PermissionFlagsBits, "ManageEmojisAndStickers">;

export const PERMISSION_NAMES = (Object.keys(PermissionFlagsBits) as Array<keyof typeof PermissionFlagsBits>).filter(
  (name): name is PermissionName => name !== "ManageEmojisAndStickers"
);

export function isPermissionName(value: string): value is PermissionName {
  return (PERMISSION_NAMES as string[]).includes(value);
}

export const CRITICAL_PERMISSIONS: readonly PermissionName[] = ["Administrator", "ManageGuild", "ManageRoles", "ManageWebhooks"];

export const HIGH_PERMISSIONS: readonly PermissionName[] = ["BanMembers", "KickMembers", "ManageChannels", "ModerateMembers"];

export const MEDIUM_PERMISSIONS: readonly PermissionName[] = [
  "MentionEveryone",
  "ManageMessages",
  "ManageThreads",
  "ManageNicknames",
  "ManageGuildExpressions",
  "ManageEvents",
  "MoveMembers",
  "MuteMembers",
  "DeafenMembers",
  "ViewAuditLog"
];

export const DEFAULT_DANGEROUS_PERMISSIONS: readonly PermissionName[] = [...CRITICAL_PERMISSIONS, ...HIGH_PERMISSIONS, "MentionEveryone"];

export const ADMINISTRATOR = PermissionFlagsBits.Administrator;

export function bitsOf(names: readonly PermissionName[]): bigint {
  let bits = 0n;
  for (const name of names) bits |= PermissionFlagsBits[name];
  return bits;
}

export function namesOf(bits: bigint): PermissionName[] {
  return PERMISSION_NAMES.filter((name) => (bits & PermissionFlagsBits[name]) === PermissionFlagsBits[name]);
}

export function has(bits: bigint, name: PermissionName): boolean {
  const flag = PermissionFlagsBits[name];
  return (bits & flag) === flag || (bits & ADMINISTRATOR) === ADMINISTRATOR;
}

export function dangerousBits(bits: bigint, dangerousMask: bigint): bigint {
  if ((bits & ADMINISTRATOR) === ADMINISTRATOR) return dangerousMask | ADMINISTRATOR;
  return bits & dangerousMask;
}

export function isDangerous(bits: bigint, dangerousMask: bigint): boolean {
  return dangerousBits(bits, dangerousMask) !== 0n;
}

export function permissionSeverity(bits: bigint): "critical" | "high" | "medium" | "low" {
  if ((bits & bitsOf(CRITICAL_PERMISSIONS)) !== 0n) return "critical";
  if ((bits & bitsOf(HIGH_PERMISSIONS)) !== 0n) return "high";
  if ((bits & bitsOf(MEDIUM_PERMISSIONS)) !== 0n) return "medium";
  return "low";
}

export function parseBits(value: unknown): bigint | null {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^\d{1,30}$/.test(value)) return BigInt(value);
  return null;
}

export const CATEGORY_PERMISSIONS: Record<ActionCategory, readonly PermissionName[]> = {
  channelCreate: ["Administrator", "ManageChannels"],
  channelDelete: ["Administrator", "ManageChannels"],
  channelUpdate: ["Administrator", "ManageChannels"],
  overwriteUpdate: ["Administrator", "ManageChannels", "ManageRoles"],
  roleCreate: ["Administrator", "ManageRoles"],
  roleDelete: ["Administrator", "ManageRoles"],
  roleUpdate: ["Administrator", "ManageRoles"],
  memberRoleUpdate: ["Administrator", "ManageRoles"],
  memberBan: ["Administrator", "BanMembers"],
  memberKick: ["Administrator", "KickMembers"],
  memberPrune: ["Administrator", "KickMembers"],
  webhookCreate: ["Administrator", "ManageWebhooks"],
  webhookUpdate: ["Administrator", "ManageWebhooks"],
  webhookDelete: ["Administrator", "ManageWebhooks"],
  botAdd: ["Administrator", "ManageGuild"],
  integrationCreate: ["Administrator", "ManageGuild"],
  integrationUpdate: ["Administrator", "ManageGuild"],
  integrationDelete: ["Administrator", "ManageGuild"],
  guildUpdate: ["Administrator", "ManageGuild"],
  commandPermissionUpdate: ["Administrator", "ManageGuild", "ManageRoles"]
};

export const ROLE_MANAGEMENT_PERMISSIONS: readonly PermissionName[] = ["Administrator", "ManageRoles"];

export const FEATURE_PERMISSIONS = {
  alerts: ["ViewChannel", "SendMessages", "EmbedLinks", "AttachFiles"],
  auditAttribution: ["ViewAuditLog"],
  roleProtection: ["ManageRoles"],
  quarantine: ["ManageRoles"],
  timeouts: ["ModerateMembers"],
  containmentKick: ["KickMembers"],
  lockdown: ["ManageGuild"],
  slowmode: ["ManageChannels"],
  webhookRemoval: ["ManageWebhooks"],
  spamCleanup: ["ManageMessages", "ReadMessageHistory"],
  recovery: ["ManageRoles", "ManageChannels"]
} as const satisfies Record<string, readonly PermissionName[]>;

export type Feature = keyof typeof FEATURE_PERMISSIONS;

export const REQUIRED_BOT_PERMISSIONS: readonly PermissionName[] = Array.from(
  new Set(Object.values(FEATURE_PERMISSIONS).flat() as PermissionName[])
);

export function missingPermissions(botBits: bigint, required: readonly PermissionName[]): PermissionName[] {
  if ((botBits & ADMINISTRATOR) === ADMINISTRATOR) return [];
  return required.filter((name) => (botBits & PermissionFlagsBits[name]) !== PermissionFlagsBits[name]);
}

export function featureAvailability(botBits: bigint): Record<Feature, PermissionName[]> {
  const result = {} as Record<Feature, PermissionName[]>;
  for (const feature of Object.keys(FEATURE_PERMISSIONS) as Feature[]) {
    result[feature] = missingPermissions(botBits, FEATURE_PERMISSIONS[feature]);
  }
  return result;
}
