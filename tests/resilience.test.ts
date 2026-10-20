import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Simulation } from "../src/simulation/harness.js";
import { AuditLogEvent, grantAudit, memberRoles, simulate, tempDir } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  vi.restoreAllMocks();
  await sim?.close();
});

describe("database failure", () => {
  it("keeps protecting, alerting and records evidence in the fallback file", async () => {
    const dir = tempDir("db-failure");
    sim = await simulate({ files: { evidenceMirror: null, evidenceFallback: path.join(dir, "fallback.jsonl"), alertFallback: path.join(dir, "alerts.jsonl") } });
    await sim.kernel.policies.context(sim.ids.guildId);
    await sim.database.close();
    sim.kernel.policies.invalidate(sim.ids.guildId);
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, sim.ids.rogueId, target, sim.ids.roles.admin);
    expect(await memberRoles(sim, target)).not.toContain(sim.ids.roles.admin);
    expect(sim.gateway.sent.length).toBeGreaterThan(0);
    const fallback = fs.readFileSync(path.join(dir, "fallback.jsonl"), "utf8").trim().split("\n");
    expect(fallback.length).toBeGreaterThan(0);
    expect(JSON.parse(fallback[0] as string).persisted).toBe(false);
    const degraded = sim.kernel.deps.health.degradedComponents().map((item) => item.component);
    expect(degraded).toEqual(expect.arrayContaining(["database", "evidence-store", "incident-store"]));
  });
});

describe("Discord API unavailability", () => {
  it("records failed actions and asks for human review without crashing", async () => {
    sim = await simulate();
    sim.gateway.fail("removeMemberRoles");
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, sim.ids.rogueId, target, sim.ids.roles.admin);
    expect(await memberRoles(sim, target)).toContain(sim.ids.roles.admin);
    const [incident] = await sim.repos.incidents.recent(sim.ids.guildId, 1);
    expect(incident?.status).toBe("needs-review");
    const events = await sim.repos.events.forIncident(sim.ids.guildId, incident?.id as string, 20);
    expect(events.some((event) => event.actionResult === "failure" && /unavailable/.test(event.error ?? ""))).toBe(true);
  });

  it("uses the fallback webhook when the alert channel cannot be reached", async () => {
    sim = await simulate();
    sim.gateway.fail("sendChannelMessage");
    await grantAudit(sim, sim.ids.rogueId, sim.memberIds[0] as string, sim.ids.roles.admin);
    expect(sim.webhookPosts.length).toBeGreaterThan(0);
    expect(JSON.stringify(sim.webhookPosts[0])).toContain("allowed_mentions");
  });

  it("survives a complete outage of every Discord call", async () => {
    sim = await simulate();
    sim.gateway.fail("all");
    await expect(sim.audit({ actionType: AuditLogEvent.MemberBanAdd, executorId: sim.ids.rogueId, targetId: sim.memberIds[0] as string })).resolves.toBeDefined();
    const member = sim.gateway.members.get(sim.memberIds[1] as string);
    if (!member) throw new Error("fixture member missing");
    await expect(sim.kernel.antiRaid.onMemberJoin({ ...member, joinedAt: sim.clock.now() })).resolves.not.toBeUndefined();
    await expect(sim.kernel.scanner.scan(sim.ids.guildId)).resolves.toBeNull();
    await expect(sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "outage", triggeredBy: sim.ids.ownerId, automatic: false })).resolves.toMatchObject({ changed: false });
  });
});
