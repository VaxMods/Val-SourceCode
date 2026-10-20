import { afterEach, describe, expect, it } from "vitest";
import { bitsOf } from "../src/discord/permissions.js";
import type { Simulation } from "../src/simulation/harness.js";
import { AuditLogEvent, grantAudit, incidentOfType, memberRoles, methods, simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

describe("mandatory scenario: unauthorized Administrator grant", () => {
  it("revokes the role from the recipient and removes only the granter's role-management access", async () => {
    sim = await simulate();
    const { ids } = sim;
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, ids.rogueId, target, ids.roles.admin, "Admin");

    expect(await memberRoles(sim, target)).not.toContain(ids.roles.admin);
    const rogueRoles = await memberRoles(sim, ids.rogueId);
    expect(rogueRoles).not.toContain(ids.roles.roleManager);
    expect(rogueRoles).toContain(ids.roles.moderator);
    expect(rogueRoles).toContain(ids.roles.channelManager);

    const incident = await incidentOfType(sim, "role.unauthorized-grant");
    expect(incident?.severity).toBe("critical");
    expect(incident?.confidence).toBe("high");
    expect(incident?.status).toBe("contained");
    expect(incident?.actorId).toBe(ids.rogueId);

    const events = await sim.repos.events.forIncident(ids.guildId, incident?.id as string, 50);
    const actions = events.filter((event) => event.eventType === "response.action");
    expect(actions.map((event) => event.action)).toEqual(["revoke-role-from-recipient", "remove-roles-granting-abused-permissions"]);
    expect(actions.every((event) => typeof event.evidence.rationale === "string" && (event.evidence.rationale as string).length > 0)).toBe(true);
    expect(sim.gateway.sent.some((item) => item.channelId === ids.channels.alerts)).toBe(true);
  });

  it("leaves a grant made by a configured security administrator untouched", async () => {
    sim = await simulate();
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, sim.ids.securityAdminId, target, sim.ids.roles.admin);
    expect(await memberRoles(sim, target)).toContain(sim.ids.roles.admin);
    expect(methods(sim)).not.toContain("removeMemberRoles");
    const authorized = await sim.repos.events.recent(sim.ids.guildId, 20);
    expect(authorized.some((event) => event.eventType === "role.grant.authorized")).toBe(true);
  });

  it("accepts a granter explicitly allowed for a protected role", async () => {
    sim = await simulate();
    await sim.repos.protectedRoles.upsert({
      guildId: sim.ids.guildId,
      roleId: sim.ids.roles.channelManager,
      allowedGranterIds: [sim.ids.rogueId],
      allowedGranterRoleIds: [],
      createdBy: sim.ids.ownerId,
      createdAt: new Date().toISOString()
    });
    sim.kernel.policies.invalidate(sim.ids.guildId);
    const target = sim.memberIds[1] as string;
    await grantAudit(sim, sim.ids.rogueId, target, sim.ids.roles.channelManager);
    expect(await memberRoles(sim, target)).toContain(sim.ids.roles.channelManager);
  });

  it("alerts but never revokes automatically when the granter cannot be identified", async () => {
    sim = await simulate();
    const target = sim.memberIds[2] as string;
    sim.gateway.grantRoleDirect(target, sim.ids.roles.admin);
    await sim.kernel.roleGuard.onMemberRolesAdded(sim.ids.guildId, target, [sim.ids.roles.admin]);
    expect(await memberRoles(sim, target)).toContain(sim.ids.roles.admin);
    const incident = await incidentOfType(sim, "role.grant-unattributed");
    expect(incident?.status).toBe("needs-review");
    expect(incident?.confidence).toBe("none");
    expect(methods(sim)).not.toContain("removeMemberRoles");
  });

  it("attributes a grant through the fetched audit log when the live audit event is missing", async () => {
    sim = await simulate();
    const target = sim.memberIds[3] as string;
    sim.gateway.grantRoleDirect(target, sim.ids.roles.admin);
    sim.gateway.recordAudit({
      id: "700000000000009999",
      actionType: AuditLogEvent.MemberRoleUpdate,
      executorId: sim.ids.rogueId,
      targetId: target,
      createdAt: sim.clock.now(),
      changes: [{ key: "$add", old: null, new: [{ id: sim.ids.roles.admin, name: "Admin" }] }]
    });
    await sim.kernel.roleGuard.onMemberRolesAdded(sim.ids.guildId, target, [sim.ids.roles.admin]);
    expect(await memberRoles(sim, target)).not.toContain(sim.ids.roles.admin);
  });

  it("evaluates a re-grant performed right after a revocation", async () => {
    sim = await simulate();
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, sim.ids.rogueId, target, sim.ids.roles.admin);
    sim.gateway.addMember({ id: "200000000000000050", username: "accomplice", roleIds: [sim.ids.roles.roleManager] });
    sim.clock.advance(2000);
    await grantAudit(sim, "200000000000000050", target, sim.ids.roles.admin);
    expect(await memberRoles(sim, target)).not.toContain(sim.ids.roles.admin);
    expect(await memberRoles(sim, "200000000000000050")).not.toContain(sim.ids.roles.roleManager);
  });

  it("restricts sensitive grants to the owner and security administrators during lockdown", async () => {
    sim = await simulate({ policy: { roleProtection: { authorizedGranterIds: ["200000000000000004"] } } });
    const target = sim.memberIds[4] as string;
    await sim.kernel.lockdown.activate({ guildId: sim.ids.guildId, reason: "test", triggeredBy: sim.ids.securityAdminId, automatic: false });
    await grantAudit(sim, sim.ids.rogueId, target, sim.ids.roles.channelManager);
    expect(await memberRoles(sim, target)).not.toContain(sim.ids.roles.channelManager);
  });

  it("only recommends in monitor mode", async () => {
    sim = await simulate({ policy: { mode: "monitor" } });
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, sim.ids.rogueId, target, sim.ids.roles.admin);
    expect(await memberRoles(sim, target)).toContain(sim.ids.roles.admin);
    expect((await incidentOfType(sim, "role.unauthorized-grant"))?.status).toBe("needs-review");
  });

  it("explains why a role above Val Protection cannot be revoked", async () => {
    sim = await simulate();
    const high = sim.gateway.addRole({ name: "Head Admin", permissions: bitsOf(["Administrator"]), position: 30 });
    const target = sim.memberIds[0] as string;
    await grantAudit(sim, sim.ids.rogueId, target, high.id);
    expect(await memberRoles(sim, target)).toContain(high.id);
    const incident = await incidentOfType(sim, "role.unauthorized-grant");
    const events = await sim.repos.events.forIncident(sim.ids.guildId, incident?.id as string, 50);
    const revoke = events.find((event) => event.action === "revoke-role-from-recipient");
    expect(revoke?.actionResult).toBe("skipped");
    expect(String(revoke?.evidence.detail)).toMatch(/above Val Protection/);
  });
});

describe("role permission changes", () => {
  it("reverts only the dangerous permissions added by an unauthorized moderator", async () => {
    sim = await simulate();
    const before = sim.gateway.roles.get(sim.ids.roles.member)?.permissions as bigint;
    const after = before | bitsOf(["ManageRoles", "ManageMessages"]);
    sim.gateway.setRolePermissionsDirect(sim.ids.roles.member, after);
    await sim.audit({
      actionType: AuditLogEvent.RoleUpdate,
      executorId: sim.ids.rogueId,
      targetId: sim.ids.roles.member,
      changes: [{ key: "permissions", old: before.toString(), new: after.toString() }]
    });
    const role = sim.gateway.roles.get(sim.ids.roles.member);
    expect(role?.permissions).toBe(before | bitsOf(["ManageMessages"]));
    expect((await incidentOfType(sim, "role.permission-escalation"))?.severity).toBe("high");
  });

  it("is honest when Discord prevents reverting Administrator", async () => {
    sim = await simulate();
    const after = bitsOf(["Administrator"]);
    sim.gateway.setRolePermissionsDirect(sim.ids.roles.member, after);
    await sim.audit({
      actionType: AuditLogEvent.RoleUpdate,
      executorId: sim.ids.rogueId,
      targetId: sim.ids.roles.member,
      changes: [{ key: "permissions", old: "0", new: after.toString() }]
    });
    expect(sim.gateway.roles.get(sim.ids.roles.member)?.permissions).toBe(after);
    const incident = await incidentOfType(sim, "role.permission-escalation");
    expect(incident?.severity).toBe("critical");
    expect(incident?.status).toBe("needs-review");
    const events = await sim.repos.events.forIncident(sim.ids.guildId, incident?.id as string, 50);
    expect(String(events.find((event) => event.action === "revert-dangerous-permissions")?.evidence.detail)).toMatch(/permissions it holds itself/);
  });

  it("strips dangerous permissions from a privileged role created without authorization", async () => {
    sim = await simulate();
    const created = sim.gateway.addRole({ name: "helper", permissions: bitsOf(["ManageWebhooks", "SendMessages"]), position: 6 });
    await sim.audit({ actionType: AuditLogEvent.RoleCreate, executorId: sim.ids.rogueId, targetId: created.id, changes: [{ key: "permissions", old: null, new: created.permissions.toString() }] });
    expect(sim.gateway.roles.get(created.id)?.permissions).toBe(bitsOf(["SendMessages"]));
  });

  it("routes decoy role grants to the honeypot instead of the role guard", async () => {
    sim = await simulate();
    await grantAudit(sim, sim.ids.rogueId, sim.memberIds[5] as string, sim.ids.roles.decoy);
    expect(await incidentOfType(sim, "role.unauthorized-grant")).toBeUndefined();
    const events = await sim.repos.events.recent(sim.ids.guildId, 10);
    expect(events.some((event) => event.eventType === "honeypot.decoy-role-granted")).toBe(true);
  });
});
