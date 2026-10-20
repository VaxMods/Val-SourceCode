import { GuildVerificationLevel } from "discord.js";
import { afterEach, describe, expect, it } from "vitest";
import { createSilentLogger } from "../src/core/logger.js";
import { HealthMonitor } from "../src/core/health.js";
import { MemoryLockManager } from "../src/security/infra/lockManager.js";
import { LockdownService } from "../src/security/lockdown/lockdownService.js";
import type { Simulation } from "../src/simulation/harness.js";
import { simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

describe("lockdown", () => {
  it("raises verification, pauses invites and restores both", async () => {
    sim = await simulate();
    const result = await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "manual test", triggeredBy: sim.ids.securityAdminId, automatic: false });
    expect(result.changed).toBe(true);
    expect(sim.gateway.guildState.verificationLevel).toBe(GuildVerificationLevel.High);
    expect(sim.gateway.guildState.invitesPaused).toBe(true);
    const ended = await sim.kernel.lockdown.deactivate(sim.ids.guildId, sim.ids.securityAdminId, "resolved");
    expect(ended.changed).toBe(true);
    expect(sim.gateway.guildState.verificationLevel).toBe(GuildVerificationLevel.Low);
    expect(sim.gateway.guildState.invitesPaused).toBe(false);
  });

  it("does not overwrite a manual change made during lockdown", async () => {
    sim = await simulate();
    await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "test", triggeredBy: sim.ids.ownerId, automatic: false });
    sim.gateway.guildState.verificationLevel = GuildVerificationLevel.VeryHigh;
    const ended = await sim.kernel.lockdown.deactivate(sim.ids.guildId, sim.ids.ownerId, "done");
    expect(sim.gateway.guildState.verificationLevel).toBe(GuildVerificationLevel.VeryHigh);
    expect(ended.actions.find((action) => action.action === "restore-verification-level")?.outcome.skipped).toBe(true);
  });

  it("is idempotent and bounded by the maximum duration", async () => {
    sim = await simulate({ policy: { lockdown: { maxDurationMinutes: 30 } } });
    const first = await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "a", triggeredBy: sim.ids.ownerId, automatic: false, durationMinutes: 600 });
    const second = await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "b", triggeredBy: sim.ids.ownerId, automatic: false });
    expect(second.changed).toBe(false);
    expect(Date.parse(first.record?.expiresAt as string) - sim.clock.now()).toBe(30 * 60000);
    sim.clock.advance(31 * 60000);
    await sim.kernel.lockdown.expireDue();
    expect(sim.kernel.lockdown.isActive(sim.ids.guildId)).toBe(false);
  });

  it("survives a restart through persisted state", async () => {
    sim = await simulate();
    await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "persist", triggeredBy: sim.ids.ownerId, automatic: false });
    const restarted = new LockdownService(
      sim.repos.lockdowns,
      sim.gateway,
      sim.kernel.policies,
      sim.kernel.evidence,
      sim.kernel.alerts,
      new MemoryLockManager(),
      sim.clock,
      createSilentLogger(),
      new HealthMonitor()
    );
    await restarted.initialize();
    expect(restarted.isActive(sim.ids.guildId)).toBe(true);
    await restarted.deactivate(sim.ids.guildId, sim.ids.ownerId, "after restart");
    expect(sim.gateway.guildState.invitesPaused).toBe(false);
  });

  it("explains missing permissions instead of failing silently", async () => {
    sim = await simulate();
    const botRole = sim.gateway.roles.get(sim.ids.roles.botRole);
    if (!botRole) throw new Error("bot role missing");
    sim.gateway.setRolePermissionsDirect(botRole.id, botRole.permissions & ~(1n << 5n));
    const result = await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "no perms", triggeredBy: sim.ids.ownerId, automatic: false });
    expect(result.actions.every((action) => action.outcome.skipped)).toBe(true);
    expect(result.actions[0]?.rationale).toMatch(/Manage Server/);
  });
});
