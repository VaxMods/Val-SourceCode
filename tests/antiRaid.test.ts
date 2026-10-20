import { afterEach, describe, expect, it } from "vitest";
import { guildPolicySchema } from "../src/config/schema.js";
import { RaidDetector } from "../src/security/antiRaid/raidDetector.js";
import { assessJoin, normalizeName, similarNames } from "../src/security/antiRaid/riskScorer.js";
import type { Simulation } from "../src/simulation/harness.js";
import { incidentOfType, methods, simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

const HOUR = 3600000;

describe("risk scoring", () => {
  it("normalises look-alike usernames", () => {
    expect(normalizeName("R41D3R_1234")).toBe("raider");
    expect(normalizeName("raider.99")).toBe("raider");
    expect(similarNames("fr33nitro_1001", "freenitro1002")).toBe(true);
    expect(similarNames("alice", "bob")).toBe(false);
  });

  it("does not consider an old account with an avatar suspicious", () => {
    const settings = guildPolicySchema.parse({}).antiRaid;
    const now = Date.UTC(2026, 9, 1);
    const result = assessJoin({ userId: "1", username: "regular", joinedAt: now, accountCreatedAt: now - 900 * 24 * HOUR, hasAvatar: true, flaggedSpammer: false }, [], settings, false, now);
    expect(result.score).toBe(0);
  });

  it("combines several signals", () => {
    const settings = guildPolicySchema.parse({}).antiRaid;
    const now = Date.UTC(2026, 9, 1);
    const recent = [0, 1, 2].map((index) => ({ userId: `r${index}`, username: `spam_bot${index}`, joinedAt: now, accountCreatedAt: now - 2 * HOUR, hasAvatar: false, flaggedSpammer: false }));
    const result = assessJoin({ userId: "x", username: "spam_bot9", joinedAt: now, accountCreatedAt: now - 2 * HOUR, hasAvatar: false, flaggedSpammer: false }, recent, settings, false, now);
    expect(result.signals.map((signal) => signal.name).sort()).toEqual(["accountAge", "creationCluster", "noAvatar", "usernameCluster"]);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  it("adapts its threshold to sustained organic traffic but caps growth", () => {
    const settings = guildPolicySchema.parse({}).antiRaid;
    const detector = new RaidDetector();
    let now = Date.UTC(2026, 9, 1);
    for (let bucket = 0; bucket < 400; bucket += 1) {
      for (let join = 0; join < 4; join += 1) {
        detector.record({ userId: `${bucket}-${join}`, username: `user${bucket}${join}`, joinedAt: now, accountCreatedAt: now - 800 * 24 * HOUR, hasAvatar: true, flaggedSpammer: false, score: 0, clustered: false }, settings, false);
        now += 7000;
      }
      now += settings.windowSeconds * 1000 - 28000;
    }
    const assessment = detector.evaluate(now, settings, false);
    expect(assessment.baseline).toBeGreaterThan(2);
    expect(assessment.threshold).toBeGreaterThan(settings.minJoinsForRaid);
    expect(assessment.detected).toBeNull();
  });
});

describe("anti-raid service", () => {
  it("detects a raid, locks down and quarantines suspects without banning", async () => {
    sim = await simulate();
    for (let index = 0; index < 20; index += 1) {
      sim.clock.advance(300);
      await sim.join({ username: `raid3r_${index}`, accountCreatedAt: sim.clock.now() - 2 * HOUR, hasAvatar: false });
    }
    const incident = await incidentOfType(sim, "raid.surge");
    expect(incident).toBeDefined();
    expect(sim.kernel.lockdown.isActive(sim.ids.guildId)).toBe(true);
    expect(sim.gateway.guildState.invitesPaused).toBe(true);
    const quarantined = sim.gateway.callsTo("addMemberRole").filter((call) => call.args[2] === sim.ids.roles.quarantine);
    expect(quarantined.length).toBeGreaterThan(5);
    expect(methods(sim)).not.toContain("kickMember");
  });

  it("does not react to normal joins", async () => {
    sim = await simulate();
    for (let index = 0; index < 15; index += 1) {
      sim.clock.advance(45000);
      await sim.join({ username: `${["nina", "omar", "paul", "quinn", "rosa"][index % 5]}${index}`, accountCreatedAt: sim.clock.now() - 400 * 24 * HOUR, hasAvatar: true });
    }
    expect(sim.kernel.antiRaid.isRaidActive(sim.ids.guildId)).toBe(false);
    expect(methods(sim)).not.toContain("addMemberRole");
  });

  it("detects a slow wave of suspicious accounts", async () => {
    sim = await simulate();
    for (let index = 0; index < 8; index += 1) {
      sim.clock.advance(60000);
      await sim.join({ username: `sleeper${index}`, accountCreatedAt: sim.clock.now() - HOUR, hasAvatar: false, flaggedSpammer: index % 2 === 0 });
    }
    expect(await incidentOfType(sim, "raid.suspicious-wave")).toBeDefined();
  });

  it("does not ban new accounts merely for being new outside a raid", async () => {
    sim = await simulate();
    sim.clock.advance(60000);
    await sim.join({ username: "brandnew", accountCreatedAt: sim.clock.now() - 1000, hasAvatar: false });
    expect(methods(sim).filter((method) => method === "addMemberRole" || method === "kickMember" || method === "timeoutMember")).toEqual([]);
  });

  it("only kicks above the configured score during a raid when kick is chosen", async () => {
    sim = await simulate({ policy: { antiRaid: { suspectAction: "kick", kickMinScore: 95 } } });
    for (let index = 0; index < 15; index += 1) {
      sim.clock.advance(200);
      await sim.join({ username: `wave_${index}`, accountCreatedAt: sim.clock.now() - 2 * HOUR, hasAvatar: false });
    }
    expect(methods(sim)).not.toContain("kickMember");
    expect(methods(sim)).toContain("addMemberRole");
  });

  it("flags rejoin attempts after a protective measure", async () => {
    sim = await simulate();
    for (let index = 0; index < 12; index += 1) {
      sim.clock.advance(300);
      await sim.join({ username: `bypass_${index}`, accountCreatedAt: sim.clock.now() - 2 * HOUR, hasAvatar: false });
    }
    const actioned = sim.gateway.callsTo("addMemberRole").map((call) => call.args[1] as string).slice(0, 3);
    for (const userId of actioned) {
      sim.gateway.members.delete(userId);
      sim.clock.advance(1000);
      await sim.join({ id: userId, username: `bypass_again_${userId.slice(-3)}`, accountCreatedAt: sim.clock.now() - 2 * HOUR, hasAvatar: false });
    }
    expect(await incidentOfType(sim, "raid.bypass-attempts")).toBeDefined();
  });

  it("ends the raid after the cooldown and keeps lockdown until expiry", async () => {
    sim = await simulate();
    for (let index = 0; index < 12; index += 1) {
      sim.clock.advance(300);
      await sim.join({ username: `burst_${index}`, accountCreatedAt: sim.clock.now() - 2 * HOUR, hasAvatar: false });
    }
    expect(sim.kernel.antiRaid.isRaidActive(sim.ids.guildId)).toBe(true);
    sim.clock.advance(6 * 60000);
    await sim.kernel.antiRaid.tick();
    expect(sim.kernel.antiRaid.isRaidActive(sim.ids.guildId)).toBe(false);
    expect((await incidentOfType(sim, "raid.surge"))?.status).toBe("monitoring");
    sim.clock.advance(3 * HOUR);
    await sim.kernel.lockdown.expireDue();
    expect(sim.kernel.lockdown.isActive(sim.ids.guildId)).toBe(false);
  });
});
