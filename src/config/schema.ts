import { z } from "zod";
import { DEFAULT_DANGEROUS_PERMISSIONS, isPermissionName, type PermissionName } from "../discord/permissions.js";

export const snowflakeSchema = z.string().regex(/^\d{17,20}$/, "must be a Discord snowflake");

const ids = () => z.array(snowflakeSchema).max(500).default([]);

const int = (min: number, max: number, fallback: number) => z.number().int().min(min).max(max).default(fallback);

const num = (min: number, max: number, fallback: number) => z.number().min(min).max(max).default(fallback);

const rule = (limit: number, windowSeconds: number) =>
  z.strictObject({ limit: int(1, 1000, limit), windowSeconds: int(5, 86400, windowSeconds) }).prefault({});

const domainSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/, "must be a domain such as example.com or *.example.com");

const permissionNameSchema = z.string().refine(isPermissionName, "unknown Discord permission name").transform((value) => value as PermissionName);

const forbiddenPattern = z
  .string()
  .min(2)
  .max(64)
  .refine((value) => value.trim().length >= 2, "pattern must contain visible characters");

export const guildPolicySchema = z.strictObject({
  mode: z.enum(["monitor", "automatic"]).default("monitor"),
  alertChannelId: snowflakeSchema.nullable().default(null),
  alertPingRoleId: snowflakeSchema.nullable().default(null),
  securityAdminIds: ids(),
  auditorRoleIds: ids(),
  staffRoleIds: ids(),
  weakeningChangesRequireOwner: z.boolean().default(true),
  antiRaid: z
    .strictObject({
      enabled: z.boolean().default(true),
      windowSeconds: int(5, 600, 30),
      minJoinsForRaid: int(3, 500, 8),
      slowWaveWindowMinutes: int(2, 240, 15),
      slowWaveSuspectCount: int(3, 500, 6),
      adaptive: z
        .strictObject({
          enabled: z.boolean().default(true),
          halfLifeMinutes: int(5, 1440, 60),
          multiplier: num(1.5, 50, 4),
          maxGrowthPerBucket: num(1.01, 3, 1.25)
        })
        .prefault({}),
      raidScoreThreshold: int(1, 100, 60),
      suspectScoreThreshold: int(10, 100, 60),
      newAccountDays: int(1, 365, 7),
      weights: z
        .strictObject({
          accountAge: int(0, 100, 35),
          noAvatar: int(0, 100, 10),
          usernameCluster: int(0, 100, 25),
          creationCluster: int(0, 100, 20),
          rejoinAfterAction: int(0, 100, 25),
          spammerFlag: int(0, 100, 40)
        })
        .prefault({}),
      suspectAction: z.enum(["none", "quarantine", "timeout", "kick"]).default("quarantine"),
      actOnlyDuringRaid: z.boolean().default(true),
      quarantineRoleId: snowflakeSchema.nullable().default(null),
      timeoutMinutes: int(1, 40320, 60),
      kickMinScore: int(70, 100, 90),
      autoLockdown: z.boolean().default(true),
      raidCooldownMinutes: int(1, 120, 5)
    })
    .prefault({}),
  antiNuke: z
    .strictObject({
      enabled: z.boolean().default(true),
      response: z.enum(["alert", "contain"]).default("contain"),
      minConfidenceToContain: z.enum(["medium", "high"]).default("high"),
      containBotsByKick: z.boolean().default(true),
      autoLockdownOnSeverity: z.enum(["never", "high", "critical"]).default("critical"),
      lockdownThresholdFactor: num(0.1, 1, 0.5),
      unattributedSpikeFactor: num(1, 10, 2),
      thresholds: z
        .strictObject({
          channelCreate: rule(6, 60),
          channelDelete: rule(3, 60),
          channelUpdate: rule(10, 60),
          overwriteUpdate: rule(12, 60),
          roleCreate: rule(5, 60),
          roleDelete: rule(3, 60),
          roleUpdate: rule(6, 60),
          memberBan: rule(4, 60),
          memberKick: rule(5, 60),
          memberPrune: rule(1, 3600),
          memberRoleUpdate: rule(20, 60),
          webhookCreate: rule(3, 300),
          webhookUpdate: rule(6, 300),
          webhookDelete: rule(3, 300),
          botAdd: rule(2, 600),
          integrationCreate: rule(2, 600),
          integrationUpdate: rule(4, 600),
          integrationDelete: rule(2, 600),
          guildUpdate: rule(4, 300),
          commandPermissionUpdate: rule(3, 600)
        })
        .prefault({})
    })
    .prefault({}),
  roleProtection: z
    .strictObject({
      enabled: z.boolean().default(true),
      treatDangerousRolesAsProtected: z.boolean().default(true),
      dangerousPermissions: z.array(permissionNameSchema).min(1).default([...DEFAULT_DANGEROUS_PERMISSIONS]),
      protectedRoleIds: ids(),
      authorizedGranterIds: ids(),
      revokeFromRecipient: z.boolean().default(true),
      granterResponse: z.enum(["none", "strip-role-management"]).default("strip-role-management"),
      minConfidenceToRevoke: z.enum(["medium", "high"]).default("high"),
      revokeWhenActorUnknown: z.boolean().default(false),
      revertUnauthorizedPermissionChanges: z.boolean().default(true),
      correlationDelayMs: int(500, 15000, 2500),
      correlationWindowSeconds: int(2, 60, 15)
    })
    .prefault({}),
  bots: z
    .strictObject({
      approvedBotIds: ids(),
      authorizedAdderIds: ids(),
      unapprovedAction: z.enum(["alert", "kick"]).default("alert"),
      kickOnlyWhenAdderUnauthorized: z.boolean().default(true)
    })
    .prefault({}),
  integrations: z
    .strictObject({
      authorizedManagerIds: ids(),
      unauthorizedWebhookAction: z.enum(["alert", "delete"]).default("alert")
    })
    .prefault({}),
  antiSpam: z
    .strictObject({
      enabled: z.boolean().default(true),
      burst: z.strictObject({ maxMessages: int(2, 100, 7), windowSeconds: int(1, 120, 6) }).prefault({}),
      duplicates: z.strictObject({ max: int(2, 50, 4), windowSeconds: int(5, 600, 30) }).prefault({}),
      maxMentions: int(1, 100, 6),
      caps: z.strictObject({ ratio: num(0.5, 1, 0.8), minLength: int(5, 2000, 20) }).prefault({}),
      maxRepeatedChars: int(5, 2000, 25),
      links: z
        .strictObject({
          blockedDomains: z.array(domainSchema).max(1000).default([]),
          allowedDomains: z.array(domainSchema).max(1000).default([]),
          flagInvites: z.boolean().default(true),
          flagShorteners: z.boolean().default(true),
          flagLookalikes: z.boolean().default(true),
          flagIpHosts: z.boolean().default(true)
        })
        .prefault({}),
      threads: z.strictObject({ max: int(1, 50, 3), windowSeconds: int(10, 3600, 300) }).prefault({}),
      strikeDecaySeconds: int(30, 86400, 600),
      timeoutMinutes: int(1, 10080, 10),
      warnCooldownSeconds: int(5, 3600, 30),
      exemptRoleIds: ids(),
      exemptChannelIds: ids(),
      floodSlowmode: z
        .strictObject({
          enabled: z.boolean().default(true),
          distinctUsers: int(2, 100, 5),
          windowSeconds: int(5, 300, 15),
          slowmodeSeconds: int(1, 21600, 10),
          durationMinutes: int(1, 360, 10)
        })
        .prefault({})
    })
    .prefault({}),
  honeypot: z
    .strictObject({
      enabled: z.boolean().default(true),
      decoyRoleIds: ids(),
      decoyChannelIds: ids(),
      forbiddenCommandPatterns: z.array(forbiddenPattern).max(50).default(["!nuke", "!massban", "!banall", "!kickall", "!raid", ".nuke"]),
      correlationWindowMinutes: int(5, 1440, 60),
      escalationScore: int(2, 50, 4),
      escalationAction: z.enum(["alert", "timeout"]).default("alert"),
      timeoutMinutes: int(1, 10080, 60)
    })
    .prefault({}),
  lockdown: z
    .strictObject({
      maxDurationMinutes: int(5, 1440, 120),
      raiseVerificationLevel: z.boolean().default(true),
      verificationLevel: z.enum(["Medium", "High", "VeryHigh"]).default("High"),
      pauseInvites: z.boolean().default(true),
      quarantineNewMembers: z.boolean().default(true),
      restrictProtectedRoleGrants: z.boolean().default(true),
      suspendNonEssential: z.boolean().default(true)
    })
    .prefault({}),
  backups: z
    .strictObject({
      enabled: z.boolean().default(true),
      intervalMinutes: int(30, 10080, 360),
      keep: int(1, 200, 14)
    })
    .prefault({}),
  logging: z.strictObject({ retentionDays: int(30, 3650, 180) }).prefault({})
});

export type GuildPolicy = z.output<typeof guildPolicySchema>;

export const globalSettingsSchema = z
  .strictObject({
    allowedGuildIds: ids(),
    commandRateLimit: z.strictObject({ limit: int(1, 100, 6), windowSeconds: int(5, 600, 30) }).prefault({}),
    schedulerTickSeconds: int(5, 120, 15),
    integrityCheckIntervalMinutes: int(15, 1440, 360),
    maxMembersForFullScan: int(100, 250000, 25000)
  })
  .prefault({});

export type GlobalSettings = z.output<typeof globalSettingsSchema>;

export const configFileSchema = z.strictObject({
  version: z.literal(1),
  global: globalSettingsSchema,
  defaults: z.record(z.string(), z.unknown()).default({}),
  guilds: z.record(snowflakeSchema, z.record(z.string(), z.unknown())).default({})
});

export type ConfigFile = z.output<typeof configFileSchema>;
