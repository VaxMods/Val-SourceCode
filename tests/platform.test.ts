import { afterEach, describe, expect, it } from "vitest";
import { ConfirmationService } from "../src/commands/confirmations.js";
import { buildSecurityCommand, REQUIRED_ACCESS } from "../src/commands/definitions.js";
import { globalSettingsSchema, guildPolicySchema } from "../src/config/schema.js";
import { REDACTED, redactSecrets, redactString } from "../src/core/redact.js";
import { normalizeAuditEntry } from "../src/discord/auditEvent.js";
import { REQUIRED_BOT_PERMISSIONS, bitsOf, featureAvailability } from "../src/discord/permissions.js";
import { FakeClock } from "../src/simulation/fakeClock.js";
import type { Simulation } from "../src/simulation/harness.js";
import { SCENARIOS, runScenarios } from "../src/simulation/ruleTester.js";
import { AuditLogEvent, fakeBotToken, fakeConnectionString, fakeWebhookUrl, incidentOfType, simulate } from "./helpers.js";

let sim: Simulation | undefined;

afterEach(async () => {
  await sim?.close();
  sim = undefined;
});

describe("secret redaction", () => {
  it("removes tokens, webhook secrets and credentials", () => {
    const text = `token ${fakeBotToken()} hook ${fakeWebhookUrl("1", "abcDEF_123", "discordapp.com/api/v10")} db ${fakeConnectionString()}`;
    const cleaned = redactString(text);
    expect(cleaned).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789ABCD");
    expect(cleaned).not.toContain("abcDEF_123");
    expect(cleaned).not.toContain("user:pass");
    expect(redactSecrets({ nested: { password: "x", list: [{ token: "y" }] } })).toEqual({ nested: { password: REDACTED, list: [{ token: REDACTED }] } });
  });
});

describe("confirmations", () => {
  it("binds a confirmation to one user, one use and a short lifetime", () => {
    const clock = new FakeClock();
    const service = new ConfirmationService(clock);
    const { row } = service.create({ guildId: "1", userId: "owner", action: "unlock", requiredAccess: "securityAdmin", execute: async () => "done" });
    const yes = (row.components[0]?.toJSON() as { custom_id: string }).custom_id;
    expect(service.consume(yes, "1", "intruder").status).toBe("foreign");
    expect(service.consume(yes, "2", "owner").status).toBe("unknown");
    expect(service.consume(yes, "1", "owner")).toMatchObject({ status: "ok", confirmed: true });
    expect(service.consume(yes, "1", "owner").status).toBe("unknown");
    const second = service.create({ guildId: "1", userId: "owner", action: "x", requiredAccess: "owner", execute: async () => "" });
    clock.advance(61000);
    expect(service.consume((second.row.components[0]?.toJSON() as { custom_id: string }).custom_id, "1", "owner").status).toBe("expired");
    expect(service.consume("vp:confirm:forged:yes", "1", "owner").status).toBe("unknown");
  });
});

describe("slash command definition", () => {
  it("declares every required subcommand with an access level", () => {
    const json = buildSecurityCommand();
    const names = (json.options ?? []).flatMap((option) =>
      "options" in option && option.type === 2 ? (option.options ?? []).map((sub) => `${option.name} ${sub.name}`) : [option.name]
    );
    expect(names.sort()).toEqual(Object.keys(REQUIRED_ACCESS).sort());
    expect(json.default_member_permissions).toBe("32");
  });
});

describe("audit normalisation and permissions", () => {
  it("normalises a discord.js audit entry", () => {
    const event = normalizeAuditEntry(
      { id: "1", action: AuditLogEvent.MessageDelete, executorId: "2", targetId: "3", reason: null, changes: [{ key: "$add", new: [{ id: "9" }] }], extra: { channel: { id: "55" }, count: 4 }, createdTimestamp: 10 },
      "100",
      "gateway"
    );
    expect(event).toMatchObject({ actionName: "MessageDelete", category: null, extra: { channelId: "55", count: 4 } });
    expect(normalizeAuditEntry({ id: "1", action: AuditLogEvent.RoleDelete, executorId: null, targetId: null, reason: null, changes: [], extra: null, createdTimestamp: 1 }, "1", "fetch").category).toBe("roleDelete");
  });

  it("reports degraded features from missing bot permissions", () => {
    const availability = featureAvailability(bitsOf(REQUIRED_BOT_PERMISSIONS.filter((name) => name !== "ManageWebhooks")));
    expect(availability.webhookRemoval).toEqual(["ManageWebhooks"]);
    expect(availability.roleProtection).toEqual([]);
    expect(REQUIRED_BOT_PERMISSIONS).not.toContain("Administrator");
  });
});

describe("security scan", () => {
  it("finds dangerous configurations", async () => {
    sim = await simulate();
    sim.gateway.setRolePermissionsDirect(sim.ids.guildId, bitsOf(["ViewChannel", "SendMessages", "MentionEveryone"]));
    sim.gateway.addRole({ name: "Cookies", permissions: bitsOf(["Administrator"]), position: 7 });
    sim.gateway.addMember({ username: "collector", roleIds: [sim.ids.roles.roleManager, sim.ids.roles.channelManager] });
    sim.gateway.addChannel({ name: "leaky", overwrites: [{ id: sim.ids.guildId, type: "role", allow: bitsOf(["ManageWebhooks"]), deny: 0n }] });
    const report = await sim.kernel.scanner.scan(sim.ids.guildId);
    const ids = report?.findings.map((finding) => finding.id) ?? [];
    expect(ids).toContain("everyone-dangerous");
    expect(ids.some((id) => id.startsWith("role-hidden-admin-"))).toBe(true);
    expect(ids.some((id) => id.startsWith("cumulative-"))).toBe(true);
    expect(ids.some((id) => id.startsWith("overwrite-"))).toBe(true);
    expect(report?.findings[0]?.severity).toBe("critical");
  });
});

describe("recovery", () => {
  it("recreates deleted roles and channels with mapped overwrites and reports dropped permissions", async () => {
    sim = await simulate();
    const vip = sim.gateway.addRole({ name: "VIP", permissions: bitsOf(["Administrator"]), position: 6 });
    sim.gateway.addChannel({ name: "vip-lounge", overwrites: [{ id: vip.id, type: "role", allow: bitsOf(["ViewChannel"]), deny: 0n }] });
    await sim.kernel.snapshots.capture(sim.ids.guildId, "manual");
    const lounge = [...sim.gateway.channels.values()].find((channel) => channel.name === "vip-lounge");
    sim.gateway.roles.delete(vip.id);
    if (lounge) sim.gateway.channels.delete(lounge.id);
    const plan = await sim.kernel.snapshots.plan(sim.ids.guildId);
    expect(plan?.integrity).toBe(true);
    expect(plan?.missingRoles.map((role) => role.name)).toEqual(["VIP"]);
    const actions = await sim.kernel.snapshots.execute(sim.ids.guildId, plan as NonNullable<typeof plan>, sim.ids.ownerId);
    expect(actions.every((action) => action.outcome.ok)).toBe(true);
    expect(actions[0]?.rationale).toMatch(/not restorable by the bot: Administrator/);
    const newRole = [...sim.gateway.roles.values()].find((role) => role.name === "VIP");
    const newChannel = [...sim.gateway.channels.values()].find((channel) => channel.name === "vip-lounge");
    expect(newRole?.id).not.toBe(vip.id);
    expect(newChannel?.overwrites[0]?.id).toBe(newRole?.id);
  });

  it("refuses a snapshot whose integrity check fails", async () => {
    sim = await simulate();
    const summary = await sim.kernel.snapshots.capture(sim.ids.guildId, "manual");
    await sim.database.db.updateTable("guild_snapshots").set({ hash: "0".repeat(64) }).where("id", "=", summary?.id as string).execute();
    const plan = await sim.kernel.snapshots.plan(sim.ids.guildId);
    expect(plan?.integrity).toBe(false);
    const actions = await sim.kernel.snapshots.execute(sim.ids.guildId, plan as NonNullable<typeof plan>, sim.ids.ownerId);
    expect(actions[0]?.outcome.skipped).toBe(true);
  });
});

describe("takeover and tampering", () => {
  it("reports deletion of the alert channel through the fallback webhook", async () => {
    sim = await simulate();
    sim.gateway.channels.delete(sim.ids.channels.alerts);
    await sim.audit({ actionType: AuditLogEvent.ChannelDelete, executorId: sim.ids.rogueId, targetId: sim.ids.channels.alerts });
    expect((await incidentOfType(sim, "tamper.alert-channel-deleted"))?.severity).toBe("critical");
    expect(sim.webhookPosts.length).toBeGreaterThan(0);
  });

  it("reports deletion of its alert messages", async () => {
    sim = await simulate();
    await sim.audit({ actionType: AuditLogEvent.MessageBulkDelete, executorId: sim.ids.rogueId, targetId: sim.ids.channels.alerts, extra: { count: 25 } });
    expect((await incidentOfType(sim, "tamper.alert-messages-deleted"))?.actorId).toBe(sim.ids.rogueId);
  });

  it("raises an alert when it is removed from a server", async () => {
    sim = await simulate();
    await sim.kernel.tamper.onBotRemoved(sim.ids.guildId, "Simulation Server");
    expect(JSON.stringify(sim.webhookPosts)).toContain("removed");
  });
});

describe("rule simulation", () => {
  it("passes every scenario with the default policy", async () => {
    const results = await runScenarios(SCENARIOS, guildPolicySchema.parse({}), globalSettingsSchema.parse({}));
    const failed = results.filter((result) => !result.passed).map((result) => `${result.name}: ${result.observations.join("; ")}`);
    expect(failed).toEqual([]);
  });
});
