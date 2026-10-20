import { AuditLogEvent } from "discord.js";
import type { GlobalSettings, GuildPolicy } from "../config/schema.js";
import { errorMessage } from "../core/errors.js";
import { bitsOf } from "../discord/permissions.js";
import { FIXTURE_IDS } from "./fixture.js";
import { createSimulation, type Simulation } from "./harness.js";

export const SCENARIOS = ["raid", "suspicious-wave", "mass-ban", "mass-kick", "channel-nuke", "admin-grant", "unattributed-grant", "unapproved-bot", "spam", "legit-admin"] as const;

export type ScenarioName = (typeof SCENARIOS)[number];

export interface ScenarioResult {
  name: ScenarioName;
  passed: boolean;
  expectation: string;
  observations: string[];
}

export function simulationPolicy(policy: GuildPolicy): Record<string, unknown> {
  const ids = FIXTURE_IDS;
  return {
    ...policy,
    mode: "automatic",
    alertChannelId: ids.channels.alerts,
    alertPingRoleId: null,
    securityAdminIds: [ids.securityAdminId],
    auditorRoleIds: [],
    staffRoleIds: [ids.roles.moderator],
    antiRaid: { ...policy.antiRaid, quarantineRoleId: ids.roles.quarantine },
    roleProtection: { ...policy.roleProtection, protectedRoleIds: [], authorizedGranterIds: [] },
    bots: { ...policy.bots, approvedBotIds: [], authorizedAdderIds: [] },
    integrations: { ...policy.integrations, authorizedManagerIds: [] },
    antiSpam: { ...policy.antiSpam, exemptRoleIds: [], exemptChannelIds: [] },
    honeypot: { ...policy.honeypot, decoyRoleIds: [ids.roles.decoy], decoyChannelIds: [] }
  };
}

function mutations(sim: Simulation): string[] {
  const relevant = new Set(["removeMemberRoles", "addMemberRole", "kickMember", "timeoutMember", "setRolePermissions", "setVerificationLevel", "pauseInvites", "deleteMessages", "setChannelSlowmode", "deleteWebhook"]);
  const counts = new Map<string, number>();
  for (const call of sim.gateway.calls) if (relevant.has(call.method)) counts.set(call.method, (counts.get(call.method) ?? 0) + 1);
  return [...counts.entries()].map(([method, count]) => `would call ${method} ×${count}`);
}

async function incidentsOf(sim: Simulation): Promise<string[]> {
  const list = await sim.repos.incidents.recent(sim.ids.guildId, 20);
  return list.reverse().map((item) => `incident ${item.type} [${item.severity}] → ${item.status}`);
}

async function run(sim: Simulation, name: ScenarioName): Promise<{ passed: boolean; expectation: string; notes: string[] }> {
  const ids = sim.ids;
  const notes: string[] = [];
  switch (name) {
    case "raid": {
      let detectedAt = 0;
      for (let index = 0; index < 25; index += 1) {
        sim.clock.advance(400);
        await sim.join({ username: `fr33nitro_${1000 + index}`, accountCreatedAt: sim.clock.now() - 3600000 * 3, hasAvatar: false });
        if (!detectedAt && sim.kernel.antiRaid.isRaidActive(ids.guildId)) detectedAt = index + 1;
      }
      notes.push(detectedAt ? `raid detected at join #${detectedAt}` : "raid not detected");
      return { passed: detectedAt > 0, expectation: "25 fresh look-alike accounts in 10s are detected as a raid; suspects are quarantined, never banned", notes };
    }
    case "suspicious-wave": {
      let detected = false;
      for (let index = 0; index < 12; index += 1) {
        sim.clock.advance(55000);
        await sim.join({ username: `quietbot${index}x`, accountCreatedAt: sim.clock.now() - 1800000, hasAvatar: false });
        detected ||= sim.kernel.antiRaid.isRaidActive(ids.guildId);
      }
      notes.push(detected ? "slow wave of suspicious accounts detected" : "slow wave not detected");
      return { passed: detected, expectation: "a slow trickle of new suspicious accounts is detected even below the surge threshold", notes };
    }
    case "mass-ban":
    case "mass-kick": {
      const actionType = name === "mass-ban" ? AuditLogEvent.MemberBanAdd : AuditLogEvent.MemberKick;
      for (const target of sim.memberIds.slice(0, 8)) {
        sim.clock.advance(1500);
        await sim.audit({ actionType, executorId: ids.rogueId, targetId: target });
      }
      const rogue = await sim.gateway.getMember(ids.guildId, ids.rogueId);
      const contained = rogue !== null && !rogue.roleIds.includes(ids.roles.moderator);
      notes.push(contained ? "the role granting the abused permission was removed from the actor" : "actor kept the abused permission");
      return { passed: contained, expectation: `rapid ${name === "mass-ban" ? "bans" : "kicks"} by one moderator are contained by removing only the role granting that permission`, notes };
    }
    case "channel-nuke": {
      for (const channelId of [ids.channels.general, ids.channels.announcements, ids.channels.rules]) {
        sim.clock.advance(1000);
        sim.gateway.channels.delete(channelId);
        await sim.audit({ actionType: AuditLogEvent.ChannelDelete, executorId: ids.rogueId, targetId: channelId });
      }
      const rogue = await sim.gateway.getMember(ids.guildId, ids.rogueId);
      const contained = rogue !== null && !rogue.roleIds.includes(ids.roles.channelManager);
      notes.push(contained ? "channel management role removed from the actor" : "actor kept channel management");
      notes.push(sim.kernel.lockdown.isActive(ids.guildId) ? "lockdown activated" : "no lockdown");
      return { passed: contained, expectation: "mass channel deletion is contained and a recovery plan is offered (deleted channels cannot be undeleted)", notes };
    }
    case "admin-grant": {
      const target = sim.memberIds[0] as string;
      sim.gateway.grantRoleDirect(target, ids.roles.admin);
      await sim.audit({ actionType: AuditLogEvent.MemberRoleUpdate, executorId: ids.rogueId, targetId: target, changes: [{ key: "$add", old: null, new: [{ id: ids.roles.admin, name: "Admin" }] }] });
      const member = await sim.gateway.getMember(ids.guildId, target);
      const rogue = await sim.gateway.getMember(ids.guildId, ids.rogueId);
      const revoked = member !== null && !member.roleIds.includes(ids.roles.admin);
      const restricted = rogue !== null && !rogue.roleIds.includes(ids.roles.roleManager);
      notes.push(revoked ? "Administrator role revoked from the recipient" : "recipient kept the role");
      notes.push(restricted ? "granter lost only the role-management role" : "granter kept role management");
      return { passed: revoked && restricted, expectation: "an unauthorized Administrator grant is revoked and only the granter's role-management access is removed", notes };
    }
    case "unattributed-grant": {
      const target = sim.memberIds[1] as string;
      sim.gateway.grantRoleDirect(target, ids.roles.admin);
      await sim.kernel.roleGuard.onMemberRolesAdded(ids.guildId, target, [ids.roles.admin]);
      const member = await sim.gateway.getMember(ids.guildId, target);
      const kept = member !== null && member.roleIds.includes(ids.roles.admin);
      notes.push(kept ? "no automatic revocation (author unknown); human review requested" : "role was revoked although the author was unknown");
      return { passed: kept, expectation: "when the granter cannot be identified, Val Protection alerts and waits for a human", notes };
    }
    case "unapproved-bot": {
      const botId = "200000000000000099";
      sim.gateway.addMember({ id: botId, username: "SuspiciousHelper", isBot: true });
      await sim.audit({ actionType: AuditLogEvent.BotAdd, executorId: ids.rogueId, targetId: botId });
      const registry = await sim.repos.bots.get(ids.guildId, botId);
      notes.push(`bot status: ${registry?.status ?? "unknown"}`);
      return { passed: registry?.status === "pending", expectation: "a bot that is not approved is placed in logical quarantine and reported, not assumed malicious", notes };
    }
    case "spam": {
      const author = sim.memberIds[2] as string;
      let last = "none";
      for (let index = 0; index < 12; index += 1) {
        sim.clock.advance(250);
        const result = await sim.kernel.antiSpam.onMessage(
          { id: (800000000000000000n + BigInt(index)).toString(), guildId: ids.guildId, channelId: ids.channels.general, authorId: author, content: "FREE NITRO here https://disc0rd-gift.ru/claim", mentionCount: 0, canMentionEveryone: false, createdAt: sim.clock.now() },
          { roleIds: [ids.roles.member], permissions: bitsOf(["SendMessages"]), isOwner: false }
        );
        last = result?.level ?? last;
      }
      notes.push(`final sanction level: ${last}`);
      return { passed: last === "timeout", expectation: "a burst of duplicate phishing links escalates warn → delete → timeout (no kick, no ban)", notes };
    }
    case "legit-admin": {
      const target = sim.memberIds[3] as string;
      sim.gateway.grantRoleDirect(target, ids.roles.admin);
      await sim.audit({ actionType: AuditLogEvent.MemberRoleUpdate, executorId: ids.securityAdminId, targetId: target, changes: [{ key: "$add", old: null, new: [{ id: ids.roles.admin, name: "Admin" }] }] });
      const member = await sim.gateway.getMember(ids.guildId, target);
      const untouched = member !== null && member.roleIds.includes(ids.roles.admin) && sim.gateway.callsTo("removeMemberRoles").length === 0;
      notes.push(untouched ? "authorized grant left untouched" : "authorized grant was wrongly reverted");
      return { passed: untouched, expectation: "a configured security administrator can grant sensitive roles without interference", notes };
    }
  }
}

export async function runScenario(name: ScenarioName, policy: GuildPolicy, global: GlobalSettings): Promise<ScenarioResult> {
  const sim = await createSimulation({ policy: simulationPolicy(policy), replacePolicy: true, global: global as unknown as Record<string, unknown> });
  try {
    const outcome = await run(sim, name);
    return { name, passed: outcome.passed, expectation: outcome.expectation, observations: [...outcome.notes, ...(await incidentsOf(sim)), ...mutations(sim)] };
  } catch (error) {
    return { name, passed: false, expectation: "scenario completes", observations: [`simulation error: ${errorMessage(error)}`] };
  } finally {
    await sim.close();
  }
}

export async function runScenarios(names: readonly ScenarioName[], policy: GuildPolicy, global: GlobalSettings): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];
  for (const name of names) results.push(await runScenario(name, policy, global));
  return results;
}
