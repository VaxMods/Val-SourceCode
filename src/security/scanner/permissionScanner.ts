import { GuildExplicitContentFilter, GuildMFALevel, GuildVerificationLevel } from "discord.js";
import type { Clock } from "../../core/clock.js";
import { SEVERITY_RANK, type Severity } from "../../core/types.js";
import type { BotRegistryRepository } from "../../database/repositories/botRegistryRepository.js";
import type { DiscordGateway, GuildInfo, MemberInfo, RoleInfo } from "../../discord/gateway.js";
import {
  ADMINISTRATOR,
  CRITICAL_PERMISSIONS,
  FEATURE_PERMISSIONS,
  bitsOf,
  dangerousBits,
  featureAvailability,
  namesOf,
  type Feature
} from "../../discord/permissions.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
}

export interface ScanReport {
  guildId: string;
  guildName: string;
  generatedAt: string;
  findings: Finding[];
  counts: Record<Severity, number>;
  scannedMembers: number | null;
  notes: string[];
}

const ADMIN_LIKE_NAME = /(admin|owner|mod|staff|manager|founder|root|sudo|perm)/i;
const OVERWRITE_DANGEROUS = bitsOf(["ManageRoles", "ManageWebhooks", "ManageChannels", "ManageThreads", "MentionEveryone"]);
const CRITICAL_FEATURES: Feature[] = ["alerts", "auditAttribution", "roleProtection"];

export class PermissionScanner {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly bots: BotRegistryRepository,
    private readonly clock: Clock
  ) {}

  async scan(guildId: string): Promise<ScanReport | null> {
    const guild = await this.gateway.getGuild(guildId);
    if (!guild) return null;
    const context = await this.policies.context(guildId);
    const roles = await this.gateway.listRoles(guildId);
    const findings: Finding[] = [];
    const notes: string[] = [];
    this.checkBot(guild, findings);
    this.checkRoles(context, guild, roles, findings);
    let scannedMembers: number | null = null;
    if (guild.memberCount <= this.policies.global.maxMembersForFullScan) {
      const members = await this.gateway.listMembers(guildId, this.policies.global.maxMembersForFullScan);
      if (members) {
        scannedMembers = members.length;
        this.checkMembers(context, guild, roles, members, findings);
      } else {
        notes.push("Member list unavailable; member-level checks were skipped (requires the Server Members intent).");
      }
    } else {
      notes.push(`Member-level checks skipped: ${guild.memberCount} members exceeds maxMembersForFullScan.`);
    }
    await this.checkChannels(context, guildId, roles, findings);
    this.checkGuildSettings(guild, findings);
    await this.checkConfiguration(context, guild, roles, findings);
    findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) counts[finding.severity] += 1;
    return { guildId, guildName: guild.name, generatedAt: new Date(this.clock.now()).toISOString(), findings: findings.slice(0, 250), counts, scannedMembers, notes };
  }

  private checkBot(guild: GuildInfo, findings: Finding[]): void {
    if ((guild.botPermissions & ADMINISTRATOR) === ADMINISTRATOR) {
      findings.push({
        id: "bot-administrator",
        severity: "medium",
        title: "Val Protection has Administrator",
        detail: "Administrator gives the bot more power than it needs; a compromised token would be catastrophic.",
        recommendation: "Remove Administrator from Val Protection's role and grant only the documented permissions."
      });
      return;
    }
    const availability = featureAvailability(guild.botPermissions);
    for (const feature of Object.keys(FEATURE_PERMISSIONS) as Feature[]) {
      const missing = availability[feature];
      if (missing.length === 0) continue;
      findings.push({
        id: `bot-missing-${feature}`,
        severity: CRITICAL_FEATURES.includes(feature) ? "high" : "medium",
        title: `Feature degraded: ${feature}`,
        detail: `Missing permissions: ${missing.join(", ")}.`,
        recommendation: `Grant ${missing.join(", ")} to Val Protection's role if you want ${feature} to work.`
      });
    }
  }

  private checkRoles(context: PolicyContext, guild: GuildInfo, roles: RoleInfo[], findings: Finding[]): void {
    const criticalMask = bitsOf(CRITICAL_PERMISSIONS);
    for (const role of roles) {
      const dangerous = dangerousBits(role.permissions, context.dangerousMask);
      if (role.isEveryone) {
        if (dangerous !== 0n) {
          findings.push({
            id: "everyone-dangerous",
            severity: "critical",
            title: "@everyone has dangerous permissions",
            detail: `@everyone grants ${namesOf(dangerous).join(", ")} to every member.`,
            recommendation: "Remove these permissions from @everyone immediately."
          });
        }
        continue;
      }
      if (dangerous === 0n) {
        if (ADMIN_LIKE_NAME.test(role.name) && !role.managed) {
          findings.push({
            id: `role-name-no-privileges-${role.id}`,
            severity: "info",
            title: `Role "${role.name}" looks privileged but is not`,
            detail: "Its name suggests staff powers, but it grants no dangerous permission. Val Protection judges roles by permissions, never by name.",
            recommendation: "No action needed unless members rely on this role for moderation."
          });
        }
        continue;
      }
      const isAdmin = (role.permissions & ADMINISTRATOR) === ADMINISTRATOR;
      if (isAdmin) {
        findings.push({
          id: `role-admin-${role.id}`,
          severity: role.managed ? "high" : "medium",
          title: `${role.managed ? "Bot role" : "Role"} "${role.name}" grants Administrator`,
          detail: role.managed ? "An integration's managed role has Administrator, which bypasses every channel permission." : "Administrator bypasses every permission and channel overwrite.",
          recommendation: role.managed ? "Remove Administrator from the bot role unless the bot strictly needs it." : "Keep Administrator to as few roles as possible and add the role to protected roles."
        });
        if (!ADMIN_LIKE_NAME.test(role.name) && !role.managed) {
          findings.push({
            id: `role-hidden-admin-${role.id}`,
            severity: "high",
            title: `Role "${role.name}" is an administrator role with an innocuous name`,
            detail: "A role whose name does not reveal its power is a classic way to hide privileges.",
            recommendation: "Rename the role or remove Administrator, and review who holds it."
          });
        }
      }
      if (role.position >= guild.botHighestRolePosition && (role.permissions & criticalMask) !== 0n) {
        findings.push({
          id: `role-above-bot-${role.id}`,
          severity: "high",
          title: `Sensitive role "${role.name}" is above Val Protection`,
          detail: `It grants ${namesOf(dangerous).join(", ")} but Val Protection cannot revoke it because of the role hierarchy.`,
          recommendation: "Move Val Protection's role above the sensitive roles it must protect (keep it below the owner's trusted roles only if intended)."
        });
      }
      if (!context.protectedRoles.has(role.id) && !context.policy.roleProtection.treatDangerousRolesAsProtected && !role.managed) {
        findings.push({
          id: `role-unprotected-${role.id}`,
          severity: "medium",
          title: `Role "${role.name}" is dangerous but not protected`,
          detail: `It grants ${namesOf(dangerous).join(", ")}.`,
          recommendation: "Protect it with /security protect-role or enable treatDangerousRolesAsProtected."
        });
      }
    }
  }

  private checkMembers(context: PolicyContext, guild: GuildInfo, roles: RoleInfo[], members: MemberInfo[], findings: Finding[]): void {
    const roleById = new Map(roles.map((role) => [role.id, role]));
    const criticalMask = bitsOf(CRITICAL_PERMISSIONS);
    const admins = members.filter((member) => !member.isBot && (member.permissions & ADMINISTRATOR) === ADMINISTRATOR);
    if (admins.length > 5) {
      findings.push({
        id: "many-administrators",
        severity: "medium",
        title: `${admins.length} human members have Administrator`,
        detail: "Every administrator account is a takeover path if compromised.",
        recommendation: "Reduce the number of administrators and use narrower moderator roles."
      });
    }
    for (const member of members) {
      if (member.id === guild.botUserId) continue;
      const dangerous = dangerousBits(member.permissions, context.dangerousMask);
      if (member.isBot && dangerous !== 0n && !this.policies.isApprovedBot(context, member.id)) {
        findings.push({
          id: `bot-unapproved-${member.id}`,
          severity: (member.permissions & ADMINISTRATOR) === ADMINISTRATOR ? "high" : "medium",
          title: `Unapproved bot ${member.username} holds dangerous permissions`,
          detail: `Permissions: ${namesOf(dangerous).join(", ")}. Not being approved does not make it malicious.`,
          recommendation: "Review the bot, then approve it with /security whitelist add or remove it."
        });
      }
      if (member.isBot || (member.permissions & ADMINISTRATOR) === ADMINISTRATOR) continue;
      const sources = new Map<bigint, Set<string>>();
      for (const roleId of member.roleIds) {
        const role = roleById.get(roleId);
        if (!role) continue;
        for (const name of namesOf(role.permissions & criticalMask)) {
          const bit = bitsOf([name]);
          sources.set(bit, (sources.get(bit) ?? new Set()).add(role.id));
        }
      }
      const criticalHeld = [...sources.keys()].reduce((acc, bit) => acc | bit, 0n);
      const coveringRole = member.roleIds.some((roleId) => {
        const role = roleById.get(roleId);
        return role !== undefined && (role.permissions & criticalHeld) === criticalHeld;
      });
      if (sources.size >= 2 && !coveringRole) {
        findings.push({
          id: `cumulative-${member.id}`,
          severity: "medium",
          title: `${member.username} accumulates critical permissions from several roles`,
          detail: `Combined roles grant ${namesOf(criticalHeld).join(", ")}, which no single role grants on its own.`,
          recommendation: "Check that this combination is intended; cumulative privileges are easy to overlook."
        });
      }
    }
  }

  private async checkChannels(context: PolicyContext, guildId: string, roles: RoleInfo[], findings: Finding[]): Promise<void> {
    const channels = await this.gateway.listChannels(guildId);
    const roleById = new Map(roles.map((role) => [role.id, role]));
    for (const channel of channels) {
      for (const overwrite of channel.overwrites) {
        const granted = overwrite.allow & OVERWRITE_DANGEROUS;
        if (granted === 0n) continue;
        const role = overwrite.type === "role" ? roleById.get(overwrite.id) : undefined;
        if (overwrite.type === "role" && role && (context.policy.staffRoleIds.includes(role.id) || role.managed)) continue;
        const everyone = role?.isEveryone ?? false;
        findings.push({
          id: `overwrite-${channel.id}-${overwrite.id}`,
          severity: everyone ? "high" : "medium",
          title: `#${channel.name}: overwrite grants ${namesOf(granted).join(", ")}`,
          detail: `${everyone ? "@everyone" : overwrite.type === "role" ? `role ${role?.name ?? overwrite.id}` : `member ${overwrite.id}`} receives channel-level management permissions.`,
          recommendation: "Remove management permissions from channel overwrites unless explicitly required."
        });
      }
    }
  }

  private checkGuildSettings(guild: GuildInfo, findings: Finding[]): void {
    if (guild.mfaLevel === GuildMFALevel.None) {
      findings.push({
        id: "mfa-not-required",
        severity: "medium",
        title: "2FA is not required for moderation",
        detail: "Moderators without two-factor authentication can perform destructive actions with only a stolen password.",
        recommendation: "The owner should enable 'Require 2FA for moderator actions' in Server Settings → Safety Setup."
      });
    }
    if (guild.verificationLevel <= GuildVerificationLevel.Low) {
      findings.push({
        id: "verification-low",
        severity: "low",
        title: "Low verification level",
        detail: "Brand-new accounts can talk immediately, which helps raids.",
        recommendation: "Consider Medium or High verification."
      });
    }
    if (guild.explicitContentFilter === GuildExplicitContentFilter.Disabled) {
      findings.push({
        id: "content-filter-off",
        severity: "low",
        title: "Explicit media filter disabled",
        detail: "Discord will not scan media from any member.",
        recommendation: "Enable the explicit media content filter for members without roles."
      });
    }
  }

  private async checkConfiguration(context: PolicyContext, guild: GuildInfo, roles: RoleInfo[], findings: Finding[]): Promise<void> {
    const roleById = new Map(roles.map((role) => [role.id, role]));
    const policy = context.policy;
    if (!policy.alertChannelId) {
      findings.push({ id: "config-no-alert-channel", severity: "high", title: "No alert channel configured", detail: "Alerts only reach the fallback webhook and local files.", recommendation: "Set alertChannelId to a private staff channel." });
    }
    for (const roleId of context.protectedRoles.keys()) {
      if (!roleById.has(roleId)) findings.push({ id: `config-missing-protected-${roleId}`, severity: "medium", title: "Protected role no longer exists", detail: `Role ${roleId} is configured as protected but was not found.`, recommendation: "Update the protected role list." });
    }
    const quarantineId = policy.antiRaid.quarantineRoleId;
    if (quarantineId) {
      const role = roleById.get(quarantineId);
      if (!role) findings.push({ id: "config-quarantine-missing", severity: "high", title: "Quarantine role missing", detail: `Role ${quarantineId} was not found.`, recommendation: "Create a quarantine role and update antiRaid.quarantineRoleId." });
      else {
        if (role.permissions !== 0n) findings.push({ id: "config-quarantine-permissions", severity: "high", title: "Quarantine role grants permissions", detail: `It grants ${namesOf(role.permissions).join(", ")}.`, recommendation: "Set the quarantine role to no permissions and deny View Channel on public channels." });
        if (role.position >= guild.botHighestRolePosition) findings.push({ id: "config-quarantine-above-bot", severity: "high", title: "Quarantine role is above Val Protection", detail: "The bot cannot assign it.", recommendation: "Move the quarantine role below Val Protection's role." });
      }
    }
    for (const decoyId of policy.honeypot.decoyRoleIds) {
      const role = roleById.get(decoyId);
      if (!role) {
        findings.push({ id: `config-decoy-missing-${decoyId}`, severity: "low", title: "Decoy role missing", detail: `Decoy role ${decoyId} was not found.`, recommendation: "Update honeypot.decoyRoleIds." });
      } else if (dangerousBits(role.permissions, context.dangerousMask) !== 0n) {
        findings.push({ id: `config-decoy-privileged-${decoyId}`, severity: "critical", title: `Decoy role "${role.name}" is privileged`, detail: `It grants ${namesOf(role.permissions).join(", ")}. It is treated as a normal sensitive role until fixed.`, recommendation: "Remove every permission from decoy roles." });
      }
    }
    try {
      const pending = await this.bots.list(context.guildId, "pending");
      if (pending.length > 0) {
        findings.push({ id: "bots-pending", severity: "medium", title: `${pending.length} bot(s) pending review`, detail: pending.slice(0, 10).map((item) => item.botId).join(", "), recommendation: "Approve trusted bots with /security whitelist add, remove the others." });
      }
    } catch {
      findings.push({ id: "bots-registry-unavailable", severity: "low", title: "Bot registry unavailable", detail: "The database could not be read.", recommendation: "Check database health." });
    }
  }
}
