import { afterEach, describe, expect, it } from "vitest";
import type { Simulation } from "../src/simulation/harness.js";
import { AuditLogEvent, incidentOfType, memberRoles, methods, simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

async function banMany(count: number, executorId: string, spacingMs = 1000): Promise<void> {
  for (const target of sim.memberIds.slice(0, count)) {
    sim.clock.advance(spacingMs);
    await sim.audit({ actionType: AuditLogEvent.MemberBanAdd, executorId, targetId: target });
  }
}

describe("anti mass-ban and mass-kick", () => {
  it("contains a mass ban by removing only the role granting Ban Members", async () => {
    sim = await simulate();
    await banMany(6, sim.ids.rogueId);
    const roles = await memberRoles(sim, sim.ids.rogueId);
    expect(roles).not.toContain(sim.ids.roles.moderator);
    expect(roles).toContain(sim.ids.roles.roleManager);
    const incident = await incidentOfType(sim, "nuke.memberBan");
    expect(incident?.severity).toBe("critical");
    expect(incident?.status).toBe("contained");
    expect(sim.kernel.lockdown.isActive(sim.ids.guildId)).toBe(true);
    expect(methods(sim).filter((method) => method === "removeMemberRoles")).toHaveLength(1);
  });

  it("contains a mass kick", async () => {
    sim = await simulate();
    for (const target of sim.memberIds.slice(0, 6)) {
      sim.clock.advance(800);
      await sim.audit({ actionType: AuditLogEvent.MemberKick, executorId: sim.ids.rogueId, targetId: target });
    }
    expect(await memberRoles(sim, sim.ids.rogueId)).not.toContain(sim.ids.roles.moderator);
    expect((await incidentOfType(sim, "nuke.memberKick"))?.status).toBe("contained");
  });

  it("ignores actions spread over time below the threshold", async () => {
    sim = await simulate();
    await banMany(6, sim.ids.rogueId, 30000);
    expect(await incidentOfType(sim, "nuke.memberBan")).toBeUndefined();
    expect(methods(sim)).not.toContain("removeMemberRoles");
  });

  it("alerts but never tries to restrict the server owner", async () => {
    sim = await simulate();
    await banMany(6, sim.ids.ownerId);
    const incident = await incidentOfType(sim, "nuke.memberBan");
    expect(incident?.summary).toMatch(/server owner/);
    expect(incident?.status).toBe("needs-review");
    expect(methods(sim)).not.toContain("removeMemberRoles");
  });

  it("logs a whitelisted moderation operation without containment", async () => {
    sim = await simulate();
    await sim.repos.whitelist.add({
      id: "wl-1",
      guildId: sim.ids.guildId,
      subjectId: sim.ids.rogueId,
      subjectType: "user",
      scopes: ["moderation"],
      reason: "approved cleanup",
      createdBy: sim.ids.ownerId,
      createdAt: new Date(sim.clock.now()).toISOString(),
      expiresAt: null
    });
    sim.kernel.policies.invalidate(sim.ids.guildId);
    await banMany(6, sim.ids.rogueId);
    expect(await incidentOfType(sim, "nuke.memberBan")).toBeUndefined();
    const events = await sim.repos.events.recent(sim.ids.guildId, 50);
    expect(events.some((event) => event.eventType === "nuke.memberBan.whitelisted")).toBe(true);
  });

  it("does not contain on medium confidence when high is required", async () => {
    sim = await simulate();
    for (const target of sim.memberIds.slice(0, 6)) {
      sim.clock.advance(1000);
      const event = sim.gateway.recordAudit({ id: `71000000000000${target.slice(-4)}`, actionType: AuditLogEvent.MemberBanAdd, executorId: sim.ids.rogueId, targetId: target, createdAt: sim.clock.now(), category: "memberBan" });
      await sim.kernel.dispatcher.dispatch({ ...event, source: "fetch" });
    }
    expect(await memberRoles(sim, sim.ids.rogueId)).toContain(sim.ids.roles.moderator);
    expect((await incidentOfType(sim, "nuke.memberBan"))?.confidence).toBe("medium");
  });

  it("reports an unattributed ban spike without acting against anyone", async () => {
    sim = await simulate();
    for (const target of sim.memberIds.slice(0, 9)) {
      sim.clock.advance(500);
      await sim.kernel.antiNuke.onUnattributedAction(sim.ids.guildId, "memberBan", target);
    }
    const incident = await incidentOfType(sim, "nuke.memberBan.unattributed-spike");
    expect(incident?.confidence).toBe("low");
    expect(incident?.status).toBe("needs-review");
    expect(methods(sim)).not.toContain("removeMemberRoles");
  });
});

describe("anti-nuke", () => {
  it("detects mass channel deletion, contains it and offers recovery", async () => {
    sim = await simulate();
    await sim.kernel.snapshots.capture(sim.ids.guildId, "manual");
    for (const channelId of [sim.ids.channels.general, sim.ids.channels.announcements, sim.ids.channels.rules]) {
      sim.clock.advance(700);
      sim.gateway.channels.delete(channelId);
      await sim.audit({ actionType: AuditLogEvent.ChannelDelete, executorId: sim.ids.rogueId, targetId: channelId });
    }
    const incident = await incidentOfType(sim, "nuke.channelDelete");
    expect(incident?.severity).toBe("critical");
    expect(incident?.summary).toMatch(/cannot be undeleted/);
    expect(await memberRoles(sim, sim.ids.rogueId)).not.toContain(sim.ids.roles.channelManager);
    expect(sim.kernel.lockdown.isActive(sim.ids.guildId)).toBe(true);
    const plan = await sim.kernel.snapshots.plan(sim.ids.guildId);
    expect(plan?.missingChannels.map((channel) => channel.name).sort()).toEqual(["announcements", "general", "rules"]);
  });

  it("kicks a bot that mass-creates channels", async () => {
    sim = await simulate();
    const bot = sim.gateway.addMember({ username: "EvilBot", isBot: true, roleIds: [sim.ids.roles.channelManager] });
    for (let index = 0; index < 7; index += 1) {
      sim.clock.advance(300);
      await sim.audit({ actionType: AuditLogEvent.ChannelCreate, executorId: bot.id, targetId: `5100000000000000${10 + index}` });
    }
    expect(await sim.gateway.getMember(sim.ids.guildId, bot.id)).toBeNull();
    expect((await incidentOfType(sim, "nuke.channelCreate"))?.status).toBe("contained");
  });

  it("does not act in monitor mode", async () => {
    sim = await simulate({ policy: { mode: "monitor" } });
    await banMany(6, sim.ids.rogueId);
    expect(await memberRoles(sim, sim.ids.rogueId)).toContain(sim.ids.roles.moderator);
    expect(sim.kernel.lockdown.isActive(sim.ids.guildId)).toBe(false);
  });

  it("ignores its own actions", async () => {
    sim = await simulate();
    for (const target of sim.memberIds.slice(0, 8)) await sim.audit({ actionType: AuditLogEvent.MemberRoleUpdate, executorId: sim.ids.botId, targetId: target, changes: [{ key: "$add", old: null, new: [{ id: sim.ids.roles.quarantine, name: "Quarantine" }] }] });
    expect(await incidentOfType(sim, "nuke.memberRoleUpdate")).toBeUndefined();
  });
});
