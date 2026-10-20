import { afterEach, describe, expect, it } from "vitest";
import { bitsOf } from "../src/discord/permissions.js";
import type { Simulation } from "../src/simulation/harness.js";
import { AuditLogEvent, fakeWebhookUrl, incidentOfType, methods, simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

const BOT_ID = "200000000000000077";

describe("unapproved bots", () => {
  it("places an unapproved bot in logical quarantine and only alerts by default", async () => {
    sim = await simulate();
    sim.gateway.addMember({ id: BOT_ID, username: "RandomBot", isBot: true });
    await sim.audit({ actionType: AuditLogEvent.BotAdd, executorId: sim.ids.rogueId, targetId: BOT_ID });
    expect((await sim.repos.bots.get(sim.ids.guildId, BOT_ID))?.status).toBe("pending");
    const incident = await incidentOfType(sim, "bot.unapproved");
    expect(incident?.summary).toMatch(/does not mean it is malicious/);
    expect(await sim.gateway.getMember(sim.ids.guildId, BOT_ID)).not.toBeNull();
  });

  it("kicks an unapproved bot added by an unauthorized account when the policy says so", async () => {
    sim = await simulate({ policy: { bots: { unapprovedAction: "kick" } } });
    const role = sim.gateway.addRole({ name: "RandomBot", permissions: bitsOf(["Administrator"]), position: 4, managed: true, botId: BOT_ID });
    sim.gateway.addMember({ id: BOT_ID, username: "RandomBot", isBot: true, roleIds: [role.id] });
    await sim.audit({ actionType: AuditLogEvent.BotAdd, executorId: sim.ids.rogueId, targetId: BOT_ID });
    expect(await sim.gateway.getMember(sim.ids.guildId, BOT_ID)).toBeNull();
    const incident = await incidentOfType(sim, "bot.unapproved");
    expect(incident?.severity).toBe("high");
    expect(incident?.status).toBe("contained");
  });

  it("keeps a bot added by an authorized person even with the kick policy", async () => {
    sim = await simulate({ policy: { bots: { unapprovedAction: "kick", authorizedAdderIds: ["200000000000000004"] } } });
    sim.gateway.addMember({ id: BOT_ID, username: "Helper", isBot: true });
    await sim.audit({ actionType: AuditLogEvent.BotAdd, executorId: sim.ids.rogueId, targetId: BOT_ID });
    expect(await sim.gateway.getMember(sim.ids.guildId, BOT_ID)).not.toBeNull();
  });

  it("accepts approved bots silently", async () => {
    sim = await simulate({ policy: { bots: { approvedBotIds: [BOT_ID] } } });
    sim.gateway.addMember({ id: BOT_ID, username: "Trusted", isBot: true });
    await sim.audit({ actionType: AuditLogEvent.BotAdd, executorId: sim.ids.rogueId, targetId: BOT_ID });
    expect((await sim.repos.bots.get(sim.ids.guildId, BOT_ID))?.status).toBe("approved");
    expect(await incidentOfType(sim, "bot.unapproved")).toBeUndefined();
  });
});

describe("webhooks and integrations", () => {
  it("deletes an unauthorized webhook when configured and never stores its token", async () => {
    sim = await simulate({ policy: { integrations: { unauthorizedWebhookAction: "delete" } } });
    const webhookId = "600000000000000001";
    sim.gateway.webhooks.add(webhookId);
    await sim.audit({
      actionType: AuditLogEvent.WebhookCreate,
      executorId: sim.ids.rogueId,
      targetId: webhookId,
      changes: [
        { key: "name", old: null, new: "Announcements" },
        { key: "channel_id", old: null, new: sim.ids.channels.general },
        { key: "url", old: null, new: fakeWebhookUrl("600000000000000001", "abcdefghijklmnopqrstuvwxyz0123456789") }
      ]
    });
    expect(sim.gateway.webhooks.has(webhookId)).toBe(false);
    const events = await sim.repos.events.recent(sim.ids.guildId, 30);
    expect(JSON.stringify(events)).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789");
    expect((await incidentOfType(sim, "webhook.unauthorized-create"))?.status).toBe("contained");
  });

  it("only logs webhooks created by authorized managers", async () => {
    sim = await simulate({ policy: { integrations: { authorizedManagerIds: ["200000000000000004"], unauthorizedWebhookAction: "delete" } } });
    sim.gateway.webhooks.add("600000000000000002");
    await sim.audit({ actionType: AuditLogEvent.WebhookCreate, executorId: sim.ids.rogueId, targetId: "600000000000000002" });
    expect(sim.gateway.webhooks.has("600000000000000002")).toBe(true);
    expect(methods(sim)).not.toContain("deleteWebhook");
  });

  it("reports changes to the permissions of Val Protection commands as tampering", async () => {
    sim = await simulate();
    await sim.audit({ actionType: AuditLogEvent.ApplicationCommandPermissionUpdate, executorId: sim.ids.rogueId, targetId: sim.ids.botId, extra: { applicationId: sim.ids.botId } });
    expect((await incidentOfType(sim, "tamper.command-permissions"))?.severity).toBe("high");
  });
});
