import { afterEach, describe, expect, it } from "vitest";
import { getPath } from "../src/config/merge.js";
import { guildPolicySchema } from "../src/config/schema.js";
import { SETTINGS, getSetting, isWeakening } from "../src/config/settings.js";
import { bitsOf } from "../src/discord/permissions.js";
import type { Actor, ChangeRequest } from "../src/security/policy/settingsService.js";
import type { Simulation } from "../src/simulation/harness.js";
import { simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

function actor(userId: string, access: Actor["access"]): Actor {
  return { userId, access };
}

async function change(as: Actor, requests: ChangeRequest[]): Promise<{ ok: boolean; message: string; weakening?: boolean }> {
  const outcome = await sim.kernel.settings.plan(sim.ids.guildId, as, requests);
  if (!outcome.ok) return { ok: false, message: outcome.error };
  const result = await sim.kernel.settings.commit(as, outcome.plan);
  return { ...result, weakening: outcome.plan.weakening };
}

async function value(path: string): Promise<unknown> {
  sim.kernel.policies.invalidate(sim.ids.guildId);
  return sim.kernel.policies.currentValue(await sim.kernel.policies.context(sim.ids.guildId), path);
}

describe("settings registry", () => {
  it("only exposes settings that exist in the policy schema", () => {
    const defaults = guildPolicySchema.parse({}) as unknown as Record<string, unknown>;
    const missing = [...SETTINGS.keys()].filter((path) => getPath(defaults, path) === undefined && !["alertChannelId", "alertPingRoleId", "antiRaid.quarantineRoleId"].includes(path));
    expect(missing).toEqual([]);
    expect(SETTINGS.size).toBeGreaterThan(100);
  });

  it("classifies weakening changes", () => {
    expect(isWeakening(getSetting("antiRaid.enabled"), true, false)).toBe(true);
    expect(isWeakening(getSetting("antiRaid.enabled"), false, true)).toBe(false);
    expect(isWeakening(getSetting("mode"), "automatic", "monitor")).toBe(true);
    expect(isWeakening(getSetting("antiNuke.thresholds.memberBan.limit"), 4, 10)).toBe(true);
    expect(isWeakening(getSetting("antiNuke.thresholds.memberBan.limit"), 4, 2)).toBe(false);
    expect(isWeakening(getSetting("antiNuke.thresholds.memberBan.windowSeconds"), 60, 10)).toBe(true);
    expect(isWeakening(getSetting("staffRoleIds"), ["1"], ["1", "2"])).toBe(true);
    expect(isWeakening(getSetting("honeypot.decoyRoleIds"), ["1", "2"], ["1"])).toBe(true);
    expect(isWeakening(getSetting("antiNuke.autoLockdownOnSeverity"), "high", "critical")).toBe(true);
    expect(isWeakening(getSetting("alertChannelId"), "1", "2")).toBe(true);
    expect(isWeakening(getSetting("alertChannelId"), null, "2")).toBe(false);
    expect(isWeakening(getSetting("logging.retentionDays"), 180, 90)).toBe(true);
  });
});

describe("settings service", () => {
  it("lets the owner configure everything from Discord without a configuration file", async () => {
    sim = await simulate({ policy: {}, replacePolicy: true });
    const owner = actor(sim.ids.ownerId, "owner");
    expect((await change(owner, [{ kind: "setting", path: "alertChannelId", value: sim.ids.channels.alerts }])).ok).toBe(true);
    expect((await change(owner, [{ kind: "setting", path: "securityAdminIds", value: [sim.ids.securityAdminId] }])).ok).toBe(true);
    expect((await change(owner, [{ kind: "setting", path: "antiRaid.quarantineRoleId", value: sim.ids.roles.quarantine }])).ok).toBe(true);
    expect((await change(owner, [{ kind: "setting", path: "mode", value: "automatic" }])).ok).toBe(true);
    expect(await value("alertChannelId")).toBe(sim.ids.channels.alerts);
    expect(await value("securityAdminIds")).toEqual([sim.ids.securityAdminId]);
    expect(await value("mode")).toBe("automatic");
    const events = await sim.repos.events.recent(sim.ids.guildId, 20);
    expect(events.filter((event) => event.eventType === "config.changed")).toHaveLength(4);
    expect(sim.gateway.sent.some((item) => item.channelId === sim.ids.channels.alerts && JSON.stringify(item.message.embeds).includes("Configuration changed"))).toBe(true);
  });

  it("keeps governance settings for the owner only", async () => {
    sim = await simulate();
    const admin = actor(sim.ids.securityAdminId, "securityAdmin");
    const result = await change(admin, [{ kind: "setting", path: "securityAdminIds", value: [sim.ids.securityAdminId, sim.ids.rogueId] }]);
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/only be changed by the server owner/);
    const events = await sim.repos.events.recent(sim.ids.guildId, 10);
    expect(events.some((event) => event.eventType === "config.refused" && event.actorId === sim.ids.securityAdminId)).toBe(true);
  });

  it("requires the owner to weaken protection unless the owner allows it", async () => {
    sim = await simulate();
    const admin = actor(sim.ids.securityAdminId, "securityAdmin");
    const owner = actor(sim.ids.ownerId, "owner");
    expect((await change(admin, [{ kind: "setting", path: "antiRaid.enabled", value: false }])).ok).toBe(false);
    expect((await change(admin, [{ kind: "setting", path: "antiNuke.thresholds.memberBan.limit", value: 2 }])).ok).toBe(true);
    expect((await change(owner, [{ kind: "setting", path: "weakeningChangesRequireOwner", value: false }])).ok).toBe(true);
    const weakened = await change(admin, [{ kind: "setting", path: "antiRaid.enabled", value: false }]);
    expect(weakened).toMatchObject({ ok: true, weakening: true });
    expect(JSON.stringify(sim.gateway.sent.at(-1)?.message.embeds)).toContain("Protection weakened");
  });

  it("refuses auditors", async () => {
    sim = await simulate();
    expect((await change(actor(sim.memberIds[0] as string, "auditor"), [{ kind: "setting", path: "antiSpam.burst.maxMessages", value: 5 }])).ok).toBe(false);
  });

  it("validates choices against the real server", async () => {
    sim = await simulate();
    const owner = actor(sim.ids.ownerId, "owner");
    const high = sim.gateway.addRole({ name: "High", permissions: 0n, position: 25 });
    const privileged = sim.gateway.addRole({ name: "Mods", permissions: bitsOf(["BanMembers"]), position: 6 });
    const bot = sim.gateway.addMember({ username: "HelperBot", isBot: true });
    expect((await change(owner, [{ kind: "setting", path: "antiRaid.quarantineRoleId", value: high.id }])).message).toMatch(/below Val Protection/);
    expect((await change(owner, [{ kind: "setting", path: "honeypot.decoyRoleIds", value: [privileged.id] }])).message).toMatch(/must have no privileges/);
    expect((await change(owner, [{ kind: "setting", path: "bots.approvedBotIds", value: [sim.ids.rogueId] }])).message).toMatch(/not a bot/);
    expect((await change(owner, [{ kind: "setting", path: "securityAdminIds", value: [bot.id] }])).message).toMatch(/is a bot/);
    expect((await change(owner, [{ kind: "setting", path: "staffRoleIds", value: [sim.ids.guildId] }])).message).toMatch(/@everyone/);
    expect((await change(owner, [{ kind: "setting", path: "antiRaid.minJoinsForRaid", value: 1 }])).ok).toBe(false);
    expect((await change(owner, [{ kind: "setting", path: "antiRaid.suspectAction", value: "kick" }, { kind: "setting", path: "antiRaid.actOnlyDuringRaid", value: false }])).message).toMatch(/kick/);
  });

  it("refuses an alert channel Val Protection cannot post in and warns the old channel when alerts move", async () => {
    sim = await simulate();
    const owner = actor(sim.ids.ownerId, "owner");
    sim.gateway.fail("canSendIn");
    expect((await change(owner, [{ kind: "setting", path: "alertChannelId", value: sim.ids.channels.general }])).message).toMatch(/cannot post/);
    sim.gateway.heal("canSendIn");
    expect((await change(owner, [{ kind: "setting", path: "alertChannelId", value: sim.ids.channels.general }])).ok).toBe(true);
    expect(sim.gateway.sent.some((item) => item.channelId === sim.ids.channels.alerts && JSON.stringify(item.message.embeds).includes("Alerts moved"))).toBe(true);
  });

  it("manages protected roles and their granters", async () => {
    sim = await simulate();
    const owner = actor(sim.ids.ownerId, "owner");
    expect((await change(owner, [{ kind: "protectedRoles", roleIds: [sim.ids.roles.moderator] }])).ok).toBe(true);
    expect((await sim.repos.protectedRoles.list(sim.ids.guildId)).map((record) => record.roleId)).toEqual([sim.ids.roles.moderator]);
    expect((await change(owner, [{ kind: "roleGranters", roleId: sim.ids.roles.channelManager, userIds: [sim.ids.rogueId], roleIds: [] }])).ok).toBe(true);
    sim.kernel.policies.invalidate(sim.ids.guildId);
    expect((await sim.kernel.policies.context(sim.ids.guildId)).protectedRoles.get(sim.ids.roles.channelManager)?.allowedGranterIds).toEqual([sim.ids.rogueId]);
    const removal = await change(owner, [{ kind: "protectedRoles", roleIds: [] }]);
    expect(removal).toMatchObject({ ok: true, weakening: true });
    expect((await change(owner, [{ kind: "protectedRoles", roleIds: [sim.ids.roles.decoy] }])).message).toMatch(/decoy/);
  });

  it("handles whitelist approvals with the same rules as the commands", async () => {
    sim = await simulate();
    const admin = actor(sim.ids.securityAdminId, "securityAdmin");
    const owner = actor(sim.ids.ownerId, "owner");
    expect((await change(owner, [{ kind: "whitelistAdd", subjectId: sim.ids.ownerId, scope: "roles", reason: "self", hours: null }])).message).toMatch(/yourself/);
    expect((await change(admin, [{ kind: "whitelistAdd", subjectId: sim.ids.rogueId, scope: "all", reason: "audit", hours: 2 }])).ok).toBe(false);
    const bot = sim.gateway.addMember({ username: "Trusted", isBot: true });
    await sim.repos.bots.upsert({ guildId: sim.ids.guildId, botId: bot.id, status: "pending", addedBy: null, addedAt: new Date().toISOString(), reviewedBy: null, reviewedAt: null, risk: {} });
    expect((await change(owner, [{ kind: "whitelistAdd", subjectId: bot.id, scope: "bots", reason: "music bot", hours: null }])).ok).toBe(true);
    expect((await sim.repos.bots.get(sim.ids.guildId, bot.id))?.status).toBe("approved");
    expect((await change(admin, [{ kind: "whitelistRevoke", subjectIds: [bot.id], reason: "test" }])).ok).toBe(true);
    expect(await sim.repos.whitelist.listActive(sim.ids.guildId, new Date().toISOString())).toEqual([]);
  });

  it("detects concurrent modifications", async () => {
    sim = await simulate();
    const owner = actor(sim.ids.ownerId, "owner");
    const first = await sim.kernel.settings.plan(sim.ids.guildId, owner, [{ kind: "setting", path: "antiSpam.maxMentions", value: 5 }]);
    expect(first.ok).toBe(true);
    await change(owner, [{ kind: "setting", path: "antiSpam.maxMentions", value: 8 }]);
    const stale = await sim.repos.settings.get(sim.ids.guildId);
    expect(await sim.repos.settings.save(sim.ids.guildId, {}, (stale?.revision ?? 1) - 1, owner.userId, new Date().toISOString())).toBe(false);
  });

  it("applies panel settings to the protections immediately", async () => {
    sim = await simulate();
    const owner = actor(sim.ids.ownerId, "owner");
    expect((await change(owner, [{ kind: "setting", path: "roleProtection.authorizedGranterIds", value: [sim.ids.rogueId] }])).ok).toBe(true);
    const target = sim.memberIds[0] as string;
    sim.gateway.grantRoleDirect(target, sim.ids.roles.admin);
    await sim.kernel.roleGuard.handleGrant({ guildId: sim.ids.guildId, targetId: target, roleIds: [sim.ids.roles.admin], actorId: sim.ids.rogueId, confidence: "high", source: "audit", auditEntryId: "799999999999999999" });
    expect((await sim.gateway.getMember(sim.ids.guildId, target))?.roleIds).toContain(sim.ids.roles.admin);
  });
});
