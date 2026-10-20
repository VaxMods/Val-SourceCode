import { ComponentType, type APIActionRowComponent, type APIComponentInMessageActionRow, type APIEmbed } from "discord.js";
import { afterEach, describe, expect, it } from "vitest";
import { ConfirmationService } from "../src/commands/confirmations.js";
import type { RouterDependencies } from "../src/commands/context.js";
import { PanelController } from "../src/commands/panel/controller.js";
import { LIST_GROUPS, NUMBER_GROUPS, listModal, nukeModal, numberModal, whitelistModal } from "../src/commands/panel/modals.js";
import { parseCustomId, type PanelView } from "../src/commands/panel/sessions.js";
import { SECTIONS } from "../src/commands/panel/views.js";
import { createSilentLogger } from "../src/core/logger.js";
import { ACTION_CATEGORIES } from "../src/core/types.js";
import type { AccessLevel } from "../src/security/policy/authorization.js";
import type { Simulation } from "../src/simulation/harness.js";
import { simulate } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

interface Logged {
  kind: string;
  payload?: unknown;
}

interface PanelPayload {
  content?: string;
  embeds: APIEmbed[];
  components: Array<{ toJSON(): APIActionRowComponent<APIComponentInMessageActionRow> }>;
}

function deps(): RouterDependencies {
  return {
    kernel: sim.kernel,
    confirmations: new ConfirmationService(sim.clock),
    logger: createSilentLogger(),
    databaseDriver: "sqlite",
    redisEnabled: false,
    backupDir: "./backups",
    startedAt: sim.clock.now(),
    integrity: new Map()
  };
}

function member(userId: string, roleIds: string[] = []) {
  return { user: { id: userId }, member: { roles: { cache: new Map(roleIds.map((id) => [id, {}])) } }, guildId: sim.ids.guildId, inCachedGuild: () => true };
}

function rows(payload: PanelPayload): Array<APIActionRowComponent<APIComponentInMessageActionRow>> {
  return payload.components.map((row) => row.toJSON());
}

function find(payload: PanelPayload, op: string, arg?: string): APIComponentInMessageActionRow & { custom_id: string } {
  for (const row of rows(payload)) {
    for (const component of row.components) {
      if (!("custom_id" in component)) continue;
      const parsed = parseCustomId(component.custom_id);
      if (parsed?.op === op && (arg === undefined || parsed.arg === arg)) return component as APIComponentInMessageActionRow & { custom_id: string };
    }
  }
  throw new Error(`component ${op}:${arg ?? ""} not found`);
}

class Driver {
  readonly controller = new PanelController(deps());
  readonly log: Logged[] = [];
  last!: PanelPayload;

  constructor(
    private readonly userId: string,
    private readonly roleIds: string[] = []
  ) {}

  async open(access: AccessLevel): Promise<PanelPayload> {
    const interaction = {
      ...member(this.userId, this.roleIds),
      deferReply: async () => this.log.push({ kind: "defer" }),
      editReply: async (payload: PanelPayload) => {
        this.last = payload;
        this.log.push({ kind: "edit", payload });
      }
    };
    await this.controller.open(interaction as never, access);
    return this.last;
  }

  private component(customId: string, type: "button" | "select", values: string[] = []) {
    return {
      ...member(this.userId, this.roleIds),
      customId,
      values,
      isButton: () => type === "button",
      isAnySelectMenu: () => type === "select",
      isStringSelectMenu: () => type === "select",
      isModalSubmit: () => false,
      deferUpdate: async () => this.log.push({ kind: "deferUpdate" }),
      editReply: async (payload: PanelPayload) => {
        this.last = payload;
        this.log.push({ kind: "edit", payload });
      },
      update: async (payload: PanelPayload) => {
        this.last = payload;
        this.log.push({ kind: "update", payload });
      },
      reply: async (payload: unknown) => this.log.push({ kind: "reply", payload }),
      showModal: async (modal: { toJSON(): unknown }) => this.log.push({ kind: "modal", payload: modal.toJSON() })
    };
  }

  async click(op: string, arg?: string): Promise<PanelPayload> {
    await this.controller.handle(this.component(find(this.last, op, arg).custom_id, "button") as never);
    return this.last;
  }

  async select(op: string, arg: string | undefined, values: string[]): Promise<PanelPayload> {
    await this.controller.handle(this.component(find(this.last, op, arg).custom_id, "select", values) as never);
    return this.last;
  }

  async submit(customId: string, text: Record<string, string>, extra: { users?: Record<string, string>; strings?: Record<string, string[]> } = {}): Promise<PanelPayload> {
    const interaction = {
      ...member(this.userId, this.roleIds),
      customId,
      isButton: () => false,
      isAnySelectMenu: () => false,
      isStringSelectMenu: () => false,
      isModalSubmit: () => true,
      isFromMessage: () => true,
      fields: {
        getTextInputValue: (id: string) => text[id] ?? "",
        getSelectedUsers: (id: string) => (extra.users?.[id] ? { first: () => ({ id: extra.users?.[id] }) } : null),
        getStringSelectValues: (id: string) => extra.strings?.[id] ?? []
      },
      deferUpdate: async () => this.log.push({ kind: "deferUpdate" }),
      editReply: async (payload: PanelPayload) => {
        this.last = payload;
        this.log.push({ kind: "edit", payload });
      },
      reply: async (payload: unknown) => this.log.push({ kind: "reply", payload }),
      update: async (payload: PanelPayload) => {
        this.last = payload;
        this.log.push({ kind: "update", payload });
      }
    };
    await this.controller.handle(interaction as never);
    return this.last;
  }

  lastModal(): { custom_id: string; title: string } {
    const modal = [...this.log].reverse().find((entry) => entry.kind === "modal");
    if (!modal) throw new Error("no modal shown");
    return modal.payload as { custom_id: string; title: string };
  }

  text(): string {
    return JSON.stringify(this.last.embeds);
  }
}

function assertDiscordLimits(payload: PanelPayload): void {
  const json = rows(payload);
  expect(json.length).toBeLessThanOrEqual(5);
  for (const row of json) {
    expect(row.components.length).toBeGreaterThan(0);
    expect(row.components.length).toBeLessThanOrEqual(5);
    const selects = row.components.filter((component) => component.type !== ComponentType.Button);
    if (selects.length > 0) expect(row.components.length).toBe(1);
    for (const component of row.components) {
      if ("custom_id" in component) {
        expect(component.custom_id.length).toBeLessThanOrEqual(100);
        expect(parseCustomId(component.custom_id)).not.toBeNull();
      }
    }
  }
  for (const embed of payload.embeds) {
    expect((embed.title ?? "").length).toBeLessThanOrEqual(256);
    expect((embed.description ?? "").length).toBeLessThanOrEqual(4096);
    expect((embed.fields ?? []).length).toBeLessThanOrEqual(25);
    for (const field of embed.fields ?? []) {
      expect(field.name.length).toBeLessThanOrEqual(256);
      expect(field.value.length).toBeGreaterThan(0);
      expect(field.value.length).toBeLessThanOrEqual(1024);
    }
    const total = (embed.title ?? "").length + (embed.description ?? "").length + (embed.footer?.text ?? "").length + (embed.fields ?? []).reduce((sum, field) => sum + field.name.length + field.value.length, 0);
    expect(total).toBeLessThanOrEqual(6000);
  }
}

describe("panel rendering", () => {
  const views: PanelView[] = ["home", ...SECTIONS.map((section) => section.id), "granters"];

  it.each(["owner", "securityAdmin", "auditor"] as const)("renders every view within Discord limits for %s", async (access) => {
    sim = await simulate();
    await sim.repos.protectedRoles.upsert({ guildId: sim.ids.guildId, roleId: sim.ids.roles.moderator, allowedGranterIds: [sim.ids.rogueId], allowedGranterRoleIds: [], createdBy: sim.ids.ownerId, createdAt: new Date().toISOString() });
    await sim.repos.whitelist.add({ id: "w1", guildId: sim.ids.guildId, subjectId: sim.ids.rogueId, subjectType: "user", scopes: ["moderation"], reason: "cleanup", createdBy: sim.ids.ownerId, createdAt: new Date().toISOString(), expiresAt: null });
    const driver = new Driver(sim.ids.ownerId);
    await driver.open(access);
    const session = [...(driver.controller.sessions as unknown as { sessions: Map<string, { view: PanelView; grantersRoleId: string | null }> }).sessions.values()][0];
    if (!session) throw new Error("no session");
    for (const view of views) {
      session.view = view;
      session.grantersRoleId = sim.ids.roles.moderator;
      const payload = await driver.controller.render(session as never, access);
      assertDiscordLimits(payload);
      const disabled = rows(payload).flatMap((row) => row.components).filter((component) => "custom_id" in component && /:(set|tog|cyc|prot|gu|gr|mod|wlrev)(:|$)/.test(component.custom_id));
      if (access === "auditor") expect(disabled.every((component) => "disabled" in component && component.disabled === true)).toBe(true);
      if (view === "access" && access === "securityAdmin") {
        expect((find(payload, "set", "securityAdminIds") as { disabled?: boolean }).disabled).toBe(true);
        expect((find(payload, "set", "staffRoleIds") as { disabled?: boolean }).disabled).toBe(false);
      }
    }
  });

  it("builds every modal within Discord limits", async () => {
    sim = await simulate();
    const value = (path: string) => sim.kernel.policies.currentValue(context, path);
    const context = await sim.kernel.policies.context(sim.ids.guildId);
    const session = { id: "abcdefghijkl" } as never;
    const modals = [
      ...Object.keys(NUMBER_GROUPS).map((group) => numberModal(session, group, value)),
      ...Object.keys(LIST_GROUPS).map((group) => listModal(session, group, value)),
      ...ACTION_CATEGORIES.map((category) => nukeModal(session, category, value)),
      whitelistModal(session)
    ];
    for (const modal of modals) {
      const json = modal.toJSON();
      expect(json.title.length).toBeLessThanOrEqual(45);
      expect(json.components.length).toBeLessThanOrEqual(5);
      expect(json.custom_id.length).toBeLessThanOrEqual(100);
    }
  });
});

describe("panel interactions", () => {
  it("lets the owner set up a server from scratch", async () => {
    sim = await simulate({ policy: {}, replacePolicy: true });
    const owner = new Driver(sim.ids.ownerId);
    const home = await owner.open("owner");
    expect(JSON.stringify(home.embeds)).toContain("Setup checklist");
    await owner.select("nav", undefined, ["general"]);
    await owner.select("set", "alertChannelId", [sim.ids.channels.alerts]);
    expect(owner.text()).toContain("Saved.");
    await owner.click("cyc", "mode");
    expect(sim.kernel.policies.currentValue(await sim.kernel.policies.context(sim.ids.guildId), "mode")).toBe("automatic");
    await owner.click("nav", "home");
    await owner.select("nav", undefined, ["access"]);
    await owner.select("set", "securityAdminIds", [sim.ids.securityAdminId]);
    expect(owner.text()).toContain("Confirm change");
    await owner.click("ok");
    expect(owner.text()).toContain("Saved.");
    sim.kernel.policies.invalidate(sim.ids.guildId);
    expect((await sim.kernel.policies.context(sim.ids.guildId)).policy.securityAdminIds).toEqual([sim.ids.securityAdminId]);
    await owner.click("nav", "home");
    await owner.select("nav", undefined, ["raid"]);
    await owner.select("set", "antiRaid.quarantineRoleId", [sim.ids.roles.quarantine]);
    await owner.click("mod", "raidThresholds");
    expect(owner.lastModal().title).toBe("Anti-raid thresholds");
    await owner.submit(owner.lastModal().custom_id, {
      "antiRaid.windowSeconds": "20",
      "antiRaid.minJoinsForRaid": "6",
      "antiRaid.raidScoreThreshold": "55",
      "antiRaid.suspectScoreThreshold": "60",
      "antiRaid.newAccountDays": "14"
    });
    expect(owner.text()).toContain("weakens");
    expect(owner.text()).toContain("Surge window");
    await owner.click("ok");
    const policy = (await sim.kernel.policies.context(sim.ids.guildId)).policy;
    expect(policy.antiRaid).toMatchObject({ windowSeconds: 20, minJoinsForRaid: 6, raidScoreThreshold: 55, newAccountDays: 14, quarantineRoleId: sim.ids.roles.quarantine });
    const home2 = await owner.click("nav", "home");
    expect(JSON.stringify(home2.embeds)).not.toContain("Setup checklist");
  });

  it("asks for confirmation before weakening and lets the user cancel", async () => {
    sim = await simulate();
    const owner = new Driver(sim.ids.ownerId);
    await owner.open("owner");
    await owner.select("nav", undefined, ["raid"]);
    await owner.click("tog", "antiRaid.enabled");
    expect(owner.text()).toContain("weakens");
    await owner.click("cancel");
    expect(sim.kernel.policies.currentValue(await sim.kernel.policies.context(sim.ids.guildId), "antiRaid.enabled")).toBe(true);
    await owner.click("tog", "antiRaid.enabled");
    await owner.click("ok");
    sim.kernel.policies.invalidate(sim.ids.guildId);
    expect(sim.kernel.policies.currentValue(await sim.kernel.policies.context(sim.ids.guildId), "antiRaid.enabled")).toBe(false);
  });

  it("refuses weakening changes from a security administrator and explains why", async () => {
    sim = await simulate();
    const admin = new Driver(sim.ids.securityAdminId, [sim.ids.roles.admin]);
    await admin.open("securityAdmin");
    await admin.select("nav", undefined, ["spam"]);
    await admin.click("tog", "antiSpam.enabled");
    expect(admin.text()).toContain("require the server owner");
    expect(sim.kernel.policies.currentValue(await sim.kernel.policies.context(sim.ids.guildId), "antiSpam.enabled")).toBe(true);
    await admin.click("mod", "spamDomains");
    await admin.submit(admin.lastModal().custom_id, { "antiSpam.links.blockedDomains": "scam.example\n*.phish.example", "antiSpam.links.allowedDomains": "" });
    expect((await sim.kernel.policies.context(sim.ids.guildId)).policy.antiSpam.links.blockedDomains).toEqual(["scam.example", "*.phish.example"]);
  });

  it("edits nuke thresholds, granters and the whitelist", async () => {
    sim = await simulate({ policy: { weakeningChangesRequireOwner: false } });
    const owner = new Driver(sim.ids.ownerId);
    await owner.open("owner");
    await owner.select("nav", undefined, ["nuke"]);
    await owner.select("nukecat", undefined, ["memberBan"]);
    expect(owner.lastModal().title).toBe("Threshold: memberBan");
    await owner.submit(owner.lastModal().custom_id, { "antiNuke.thresholds.memberBan.limit": "3", "antiNuke.thresholds.memberBan.windowSeconds": "120" });
    expect((await sim.kernel.policies.context(sim.ids.guildId)).policy.antiNuke.thresholds.memberBan).toEqual({ limit: 3, windowSeconds: 120 });
    await owner.click("nav", "home");
    await owner.select("nav", undefined, ["roles"]);
    await owner.select("prot", undefined, [sim.ids.roles.moderator]);
    await owner.select("gsel", undefined, [sim.ids.roles.moderator]);
    await owner.select("gu", sim.ids.roles.moderator, [sim.ids.rogueId]);
    await owner.click("ok");
    sim.kernel.policies.invalidate(sim.ids.guildId);
    expect((await sim.kernel.policies.context(sim.ids.guildId)).protectedRoles.get(sim.ids.roles.moderator)?.allowedGranterIds).toEqual([sim.ids.rogueId]);
    await owner.click("nav", "roles");
    await owner.click("nav", "home");
    await owner.select("nav", undefined, ["whitelist"]);
    await owner.click("mod", "wladd");
    await owner.submit(owner.lastModal().custom_id, { reason: "planned cleanup", hours: "2" }, { users: { subject: sim.ids.rogueId }, strings: { scope: ["moderation"] } });
    await owner.click("ok");
    expect((await sim.repos.whitelist.listActive(sim.ids.guildId, new Date(sim.clock.now()).toISOString())).map((entry) => entry.scopes)).toEqual([["moderation"]]);
    expect(owner.text()).toContain("moderation");
    await owner.select("wlrev", undefined, [sim.ids.rogueId]);
    expect(await sim.repos.whitelist.listActive(sim.ids.guildId, new Date(sim.clock.now()).toISOString())).toEqual([]);
  });

  it("keeps auditors read-only even if they forge an interaction", async () => {
    sim = await simulate({ policy: { auditorRoleIds: ["400000000000000008"] } });
    const auditor = new Driver(sim.memberIds[0] as string, [sim.ids.roles.member]);
    await auditor.open("auditor");
    await auditor.select("nav", undefined, ["general"]);
    await auditor.click("cyc", "mode");
    expect(auditor.text()).toContain("Read-only");
    expect(sim.kernel.policies.currentValue(await sim.kernel.policies.context(sim.ids.guildId), "mode")).toBe("automatic");
  });

  it("rejects expired panels and panels of another user", async () => {
    sim = await simulate();
    const owner = new Driver(sim.ids.ownerId);
    await owner.open("owner");
    const intruder = new Driver(sim.ids.rogueId);
    intruder.last = owner.last;
    await intruder.select("nav", undefined, ["general"]);
    expect(intruder.log.at(-1)?.kind).toBe("update");
    expect(JSON.stringify(intruder.log.at(-1)?.payload)).toContain("expired");
    sim.clock.advance(31 * 60000);
    await owner.select("nav", undefined, ["general"]);
    expect(JSON.stringify(owner.log.at(-1)?.payload)).toContain("expired");
  });
});
