import { afterEach, describe, expect, it } from "vitest";
import { bitsOf } from "../src/discord/permissions.js";
import type { Simulation } from "../src/simulation/harness.js";
import { AuditLogEvent, incidentOfType, simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

describe("honeypot", () => {
  it("treats a single unauthorized command as a probable mistake", async () => {
    sim = await simulate();
    const verdict = await sim.kernel.honeypot.signal({ guildId: sim.ids.guildId, userId: sim.memberIds[0] as string, kind: "unauthorized-command", context: { command: "lockdown" } });
    expect(verdict).toBe("probable-mistake");
    expect(sim.gateway.sent).toHaveLength(0);
  });

  it("escalates correlated interactions with several traps", async () => {
    sim = await simulate({ policy: { honeypot: { escalationAction: "timeout" } } });
    const user = sim.memberIds[1] as string;
    await sim.kernel.honeypot.signal({ guildId: sim.ids.guildId, userId: user, kind: "forbidden-command", context: {} });
    await sim.kernel.honeypot.signal({ guildId: sim.ids.guildId, userId: user, kind: "unauthorized-command", context: {} });
    const verdict = await sim.kernel.honeypot.signal({ guildId: sim.ids.guildId, userId: user, kind: "foreign-confirmation", context: {} });
    expect(verdict).toBe("likely-malicious");
    expect((await incidentOfType(sim, "honeypot.escalation"))?.severity).toBe("high");
    expect(sim.gateway.callsTo("timeoutMember")).toHaveLength(1);
  });

  it("never times out staff members", async () => {
    sim = await simulate({ policy: { honeypot: { escalationAction: "timeout", escalationScore: 2 } } });
    await sim.kernel.honeypot.signal({ guildId: sim.ids.guildId, userId: sim.ids.rogueId, kind: "foreign-confirmation", context: {} });
    await sim.kernel.honeypot.signal({ guildId: sim.ids.guildId, userId: sim.ids.rogueId, kind: "foreign-confirmation", context: {} });
    expect(sim.gateway.callsTo("timeoutMember")).toHaveLength(0);
  });

  it("restores a decoy role that received permissions", async () => {
    sim = await simulate();
    const added = bitsOf(["ManageMessages"]);
    sim.gateway.setRolePermissionsDirect(sim.ids.roles.decoy, added);
    await sim.audit({ actionType: AuditLogEvent.RoleUpdate, executorId: sim.ids.rogueId, targetId: sim.ids.roles.decoy, changes: [{ key: "permissions", old: "0", new: added.toString() }] });
    expect(sim.gateway.roles.get(sim.ids.roles.decoy)?.permissions).toBe(0n);
    expect((await incidentOfType(sim, "honeypot.decoy-privileged"))?.severity).toBe("critical");
  });

  it("matches forbidden commands without regular expressions", async () => {
    sim = await simulate();
    const context = await sim.kernel.policies.context(sim.ids.guildId);
    expect(sim.kernel.honeypot.matchForbiddenCommand(context, "!nuke everything")).toBe("!nuke");
    expect(sim.kernel.honeypot.matchForbiddenCommand(context, "talking about !nuke")).toBeNull();
    expect(sim.kernel.honeypot.matchForbiddenCommand(context, "!nukes")).toBeNull();
  });
});
