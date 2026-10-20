import {
  MessageFlags,
  type AnySelectMenuInteraction,
  type ButtonInteraction,
  type ChatInputCommandInteraction,
  type ModalSubmitInteraction
} from "discord.js";
import { getSetting } from "../../config/settings.js";
import { errorMessage } from "../../core/errors.js";
import { WHITELIST_SCOPES, type WhitelistScope } from "../../core/types.js";
import { hasAccess, resolveAccess, type AccessLevel } from "../../security/policy/authorization.js";
import type { ChangeRequest } from "../../security/policy/settingsService.js";
import type { RouterDependencies } from "../context.js";
import { LIST_GROUPS, MAX_TEXT, NUMBER_GROUPS, isActionCategory, listModal, listModalText, numberModal, nukeModal, whitelistModal } from "./modals.js";
import { PanelSessions, parseCustomId, type PanelSession } from "./sessions.js";
import { isPanelView, renderPanel, type RenderedPanel } from "./views.js";

type PanelInteraction = ButtonInteraction<"cached"> | AnySelectMenuInteraction<"cached"> | ModalSubmitInteraction<"cached">;

const MODAL_OPS = new Set(["mod", "nukecat"]);

export class PanelController {
  readonly sessions: PanelSessions;

  constructor(private readonly deps: RouterDependencies) {
    this.sessions = new PanelSessions(deps.kernel.deps.clock);
  }

  async open(interaction: ChatInputCommandInteraction<"cached">, access: AccessLevel): Promise<void> {
    const session = this.sessions.open(interaction.guildId, interaction.user.id);
    await interaction.deferReply({ flags: MessageFlags.Ephemeral });
    await this.deps.kernel.evidence.append({
      guildId: interaction.guildId,
      eventType: "panel.opened",
      severity: "info",
      actorId: interaction.user.id,
      confidence: "high",
      evidence: { access }
    });
    await interaction.editReply(await this.render(session, access));
  }

  async handle(interaction: ButtonInteraction | AnySelectMenuInteraction | ModalSubmitInteraction): Promise<void> {
    const parsed = parseCustomId(interaction.customId);
    if (!parsed) return;
    if (!interaction.inCachedGuild()) {
      await interaction.reply({ content: "This panel only works inside a server.", flags: MessageFlags.Ephemeral });
      return;
    }
    const session = this.sessions.get(parsed.sessionId, interaction.guildId, interaction.user.id);
    if (!session) {
      await this.expired(interaction);
      return;
    }
    const { kernel } = this.deps;
    const used = await kernel.deps.counters.hit(`panel:${interaction.guildId}:${interaction.user.id}`, 30000, kernel.deps.clock.now());
    if (used > 60) {
      await interaction.reply({ content: "Too many panel actions; wait a few seconds.", flags: MessageFlags.Ephemeral });
      return;
    }
    const access = await this.accessOf(interaction);
    if (MODAL_OPS.has(parsed.op)) {
      await this.openModal(interaction, session, access, parsed.op, parsed.arg);
      return;
    }
    if (interaction.isModalSubmit() && !interaction.isFromMessage()) {
      await interaction.reply({ content: "This form is no longer attached to a panel; run /security panel again.", flags: MessageFlags.Ephemeral });
      return;
    }
    await interaction.deferUpdate();
    try {
      await this.dispatch(interaction, session, access, parsed.op, parsed.arg);
    } catch (error) {
      this.deps.logger.error({ err: errorMessage(error), op: parsed.op }, "Panel action failed");
      session.notice = { ok: false, text: "The action failed; the error was logged." };
    }
    if (parsed.op === "close") return;
    await interaction.editReply(await this.render(session, await this.accessOf(interaction)));
  }

  private async dispatch(interaction: PanelInteraction, session: PanelSession, access: AccessLevel, op: string, arg: string | null): Promise<void> {
    const values = interaction.isAnySelectMenu() ? [...interaction.values] : [];
    switch (op) {
      case "nav": {
        const target = arg ?? values[0] ?? "home";
        if (isPanelView(target)) {
          session.view = target;
          session.notice = null;
        }
        return;
      }
      case "refresh":
        session.notice = null;
        return;
      case "close":
        this.sessions.close(session.id);
        await interaction.editReply({ content: "Panel closed.", embeds: [], components: [] });
        return;
      case "cancel":
        session.pending = null;
        session.notice = { ok: true, text: "Cancelled; nothing was changed." };
        return;
      case "ok":
        await this.confirm(session, interaction.user.id, access);
        return;
      case "test": {
        if (!this.requireEditor(session, access)) return;
        const delivery = await this.deps.kernel.alerts.send({
          guildId: session.guildId,
          severity: "info",
          title: "Test alert",
          description: `Test requested by <@${interaction.user.id}> from the control panel.`
        });
        session.notice = { ok: delivery === "channel", text: delivery === "channel" ? "Test alert posted in the alert channel." : `The alert channel could not be used; delivered via: ${delivery}.` };
        return;
      }
      case "set": {
        if (!arg) return;
        const definition = getSetting(arg);
        const kind = definition.kind.type;
        const value = kind === "channel" || kind === "role" || kind === "enum" ? (values[0] ?? null) : values;
        await this.apply(session, interaction.user.id, access, [{ kind: "setting", path: arg, value }]);
        return;
      }
      case "tog": {
        if (!arg) return;
        const context = await this.deps.kernel.policies.context(session.guildId);
        const current = this.deps.kernel.policies.currentValue(context, arg) === true;
        await this.apply(session, interaction.user.id, access, [{ kind: "setting", path: arg, value: !current }]);
        return;
      }
      case "cyc": {
        if (!arg) return;
        const definition = getSetting(arg);
        if (definition.kind.type !== "enum") return;
        const context = await this.deps.kernel.policies.context(session.guildId);
        const current = String(this.deps.kernel.policies.currentValue(context, arg));
        const options = definition.kind.values;
        const next = options[(options.indexOf(current) + 1) % options.length];
        await this.apply(session, interaction.user.id, access, [{ kind: "setting", path: arg, value: next }]);
        return;
      }
      case "prot":
        await this.apply(session, interaction.user.id, access, [{ kind: "protectedRoles", roleIds: values }]);
        return;
      case "gsel":
        session.grantersRoleId = values[0] ?? null;
        session.view = "granters";
        session.notice = null;
        return;
      case "gu":
      case "gr": {
        if (!arg) return;
        const rule = (await this.deps.kernel.policies.context(session.guildId)).protectedRoles.get(arg);
        await this.apply(session, interaction.user.id, access, [
          {
            kind: "roleGranters",
            roleId: arg,
            userIds: op === "gu" ? values : (rule?.allowedGranterIds ?? []),
            roleIds: op === "gr" ? values : (rule?.allowedGranterRoleIds ?? [])
          }
        ]);
        return;
      }
      case "wlrev":
        await this.apply(session, interaction.user.id, access, [{ kind: "whitelistRevoke", subjectIds: values, reason: "revoked from the control panel" }]);
        return;
      case "sub":
        if (interaction.isModalSubmit() && arg) await this.submitModal(interaction, session, access, arg);
        return;
      default:
        return;
    }
  }

  private async submitModal(interaction: ModalSubmitInteraction<"cached">, session: PanelSession, access: AccessLevel, group: string): Promise<void> {
    const fields = interaction.fields;
    if (group === "wladd") {
      const subject = fields.getSelectedUsers("subject")?.first();
      const scope = fields.getStringSelectValues("scope")[0] ?? "";
      const hoursText = fields.getTextInputValue("hours").trim();
      if (!subject) {
        session.notice = { ok: false, text: "Choose a person or bot." };
        return;
      }
      if (!(WHITELIST_SCOPES as readonly string[]).includes(scope)) {
        session.notice = { ok: false, text: "Choose a valid scope." };
        return;
      }
      if (hoursText !== "" && !/^\d{1,3}$/.test(hoursText)) {
        session.notice = { ok: false, text: "Hours must be a whole number between 1 and 720." };
        return;
      }
      await this.apply(session, interaction.user.id, access, [
        { kind: "whitelistAdd", subjectId: subject.id, scope: scope as WhitelistScope, reason: fields.getTextInputValue("reason"), hours: hoursText === "" ? null : Number.parseInt(hoursText, 10) }
      ]);
      return;
    }
    const paths = group.startsWith("nuke:")
      ? [`antiNuke.thresholds.${group.slice(5)}.limit`, `antiNuke.thresholds.${group.slice(5)}.windowSeconds`]
      : (NUMBER_GROUPS[group]?.paths ?? LIST_GROUPS[group]?.paths ?? []);
    if (paths.length === 0) return;
    const requests: ChangeRequest[] = paths.map((path) => ({ kind: "setting", path, value: fields.getTextInputValue(path) }));
    await this.apply(session, interaction.user.id, access, requests);
  }

  private async openModal(interaction: PanelInteraction, session: PanelSession, access: AccessLevel, op: string, arg: string | null): Promise<void> {
    if (interaction.isModalSubmit()) return;
    if (!hasAccess(access, "securityAdmin")) {
      await interaction.reply({ content: "Read-only: you need the security administrator access level.", flags: MessageFlags.Ephemeral });
      return;
    }
    const context = await this.deps.kernel.policies.context(session.guildId);
    const value = (path: string) => this.deps.kernel.policies.currentValue(context, path);
    if (op === "nukecat") {
      const category = interaction.isStringSelectMenu() ? interaction.values[0] : undefined;
      if (!category || !isActionCategory(category)) return;
      await interaction.showModal(nukeModal(session, category, value));
      return;
    }
    if (arg === "wladd") {
      await interaction.showModal(whitelistModal(session));
      return;
    }
    if (arg && NUMBER_GROUPS[arg]) {
      await interaction.showModal(numberModal(session, arg, value));
      return;
    }
    const list = arg ? LIST_GROUPS[arg] : undefined;
    if (arg && list) {
      if (list.paths.some((path) => listModalText(value(path)).length > MAX_TEXT)) {
        await interaction.reply({ content: "This list is too long to edit in a Discord form; edit it in the configuration file.", flags: MessageFlags.Ephemeral });
        return;
      }
      await interaction.showModal(listModal(session, arg, value));
    }
  }

  private async apply(session: PanelSession, userId: string, access: AccessLevel, requests: ChangeRequest[]): Promise<void> {
    if (!this.requireEditor(session, access)) return;
    const outcome = await this.deps.kernel.settings.plan(session.guildId, { userId, access }, requests);
    if (!outcome.ok) {
      session.notice = { ok: outcome.error === "Nothing changed.", text: outcome.error };
      return;
    }
    const plan = outcome.plan;
    if (plan.weakening || plan.changes.some((change) => change.ownerOnly)) {
      session.pending = plan;
      session.notice = null;
      return;
    }
    const result = await this.deps.kernel.settings.commit({ userId, access }, plan);
    session.notice = { ok: result.ok, text: result.ok ? `Saved. ${result.message}${plan.notes.length > 0 ? `\n${plan.notes.map((note) => `• ${note}`).join("\n")}` : ""}` : result.message };
  }

  private async confirm(session: PanelSession, userId: string, access: AccessLevel): Promise<void> {
    const plan = session.pending;
    session.pending = null;
    if (!plan) return;
    const result = await this.deps.kernel.settings.commit({ userId, access }, plan);
    session.notice = { ok: result.ok, text: result.ok ? `Saved. ${result.message}` : result.message };
  }

  private requireEditor(session: PanelSession, access: AccessLevel): boolean {
    if (hasAccess(access, "securityAdmin")) return true;
    session.notice = { ok: false, text: "Read-only: you need the security administrator access level." };
    return false;
  }

  private async accessOf(interaction: PanelInteraction): Promise<AccessLevel> {
    const policy = await this.deps.kernel.policies.context(interaction.guildId);
    const guild = await this.deps.kernel.deps.gateway.getGuild(interaction.guildId);
    if (!guild) return "none";
    return resolveAccess(policy, guild, interaction.user.id, [...interaction.member.roles.cache.keys()]);
  }

  private async expired(interaction: ButtonInteraction | AnySelectMenuInteraction | ModalSubmitInteraction): Promise<void> {
    const content = "This panel expired or was replaced. Run `/security panel` again.";
    if (interaction.isModalSubmit()) {
      if (interaction.isFromMessage()) await interaction.update({ content, embeds: [], components: [] });
      else await interaction.reply({ content, flags: MessageFlags.Ephemeral });
      return;
    }
    await interaction.update({ content, embeds: [], components: [] });
  }

  async render(session: PanelSession, access: AccessLevel): Promise<RenderedPanel & { content: string }> {
    const { kernel } = this.deps;
    if (!hasAccess(access, "auditor")) {
      this.sessions.close(session.id);
      return { content: "You no longer have access to this panel.", embeds: [], components: [] };
    }
    const context = await kernel.policies.context(session.guildId);
    const guild = await kernel.deps.gateway.getGuild(session.guildId);
    const roles = await kernel.deps.gateway.listRoles(session.guildId);
    const tableRoles = await kernel.deps.repos.protectedRoles.list(session.guildId);
    const memberNames = new Map<string, string>();
    if (session.view === "whitelist") {
      for (const entry of context.whitelist.slice(0, 25)) {
        if (memberNames.has(entry.subjectId)) continue;
        const member = await kernel.deps.gateway.getMember(session.guildId, entry.subjectId);
        if (member) memberNames.set(entry.subjectId, member.username);
      }
    }
    const rendered = renderPanel({
      session,
      context,
      access,
      guildName: guild?.name ?? session.guildId,
      roles,
      tableRoles,
      memberNames,
      lockdownActive: kernel.lockdown.isActive(session.guildId),
      value: (path) => kernel.policies.currentValue(context, path)
    });
    session.notice = null;
    return { content: "", ...rendered };
  }
}
