import { MessageFlags, type AutocompleteInteraction, type ButtonInteraction, type ChatInputCommandInteraction, type Interaction } from "discord.js";
import { errorMessage } from "../core/errors.js";
import { hasAccess, resolveAccess } from "../security/policy/authorization.js";
import { ConfirmationService } from "./confirmations.js";
import type { CommandContext, CommandHandler, RouterDependencies } from "./context.js";
import { COMMAND_NAME, REQUIRED_ACCESS } from "./definitions.js";
import { backupStatusHandler, incidentHandler, logsHandler, rolesHandler, statusHandler } from "./handlers/overview.js";
import { lockdownHandler, recoverHandler, scanHandler, testHandler, unlockHandler } from "./handlers/operations.js";
import { configAutocomplete, configHandler, protectRoleHandler, whitelistAddHandler, whitelistRemoveHandler } from "./handlers/policy.js";
import { PanelController } from "./panel/controller.js";
import { PANEL_PREFIX } from "./panel/sessions.js";

const HANDLERS: Record<string, CommandHandler> = {
  status: statusHandler,
  scan: scanHandler,
  lockdown: lockdownHandler,
  unlock: unlockHandler,
  logs: logsHandler,
  config: configHandler,
  "whitelist add": whitelistAddHandler,
  "whitelist remove": whitelistRemoveHandler,
  roles: rolesHandler,
  "protect-role": protectRoleHandler,
  incident: incidentHandler,
  test: testHandler,
  "backup-status": backupStatusHandler,
  recover: recoverHandler
};

export class CommandRouter {
  readonly panel: PanelController;

  constructor(private readonly deps: RouterDependencies) {
    this.panel = new PanelController(deps);
  }

  async handle(interaction: Interaction): Promise<void> {
    if (interaction.isAutocomplete()) {
      await this.handleAutocomplete(interaction);
      return;
    }
    if ((interaction.isButton() || interaction.isAnySelectMenu() || interaction.isModalSubmit()) && interaction.customId.startsWith(PANEL_PREFIX)) {
      await this.panel.handle(interaction);
      return;
    }
    if (interaction.isButton() && ConfirmationService.owns(interaction.customId)) {
      await this.handleButton(interaction);
      return;
    }
    if (!interaction.isChatInputCommand() || interaction.commandName !== COMMAND_NAME) return;
    await this.handleCommand(interaction);
  }

  private async handleCommand(interaction: ChatInputCommandInteraction): Promise<void> {
    const { kernel, logger } = this.deps;
    if (!interaction.inCachedGuild()) {
      await interaction.reply({ content: "Val Protection commands only work inside a server.", flags: MessageFlags.Ephemeral });
      return;
    }
    const guildId = interaction.guildId;
    const userId = interaction.user.id;
    if (!kernel.policies.isGuildAllowed(guildId)) {
      await interaction.reply({ content: "Val Protection is not enabled for this server.", flags: MessageFlags.Ephemeral });
      return;
    }
    const group = interaction.options.getSubcommandGroup(false);
    const sub = interaction.options.getSubcommand(true);
    const name = group ? `${group} ${sub}` : sub;
    const limit = kernel.policies.global.commandRateLimit;
    const used = await kernel.deps.counters.hit(`commands:${guildId}:${userId}`, limit.windowSeconds * 1000, kernel.deps.clock.now());
    if (used > limit.limit) {
      await interaction.reply({ content: `Too many commands. Wait ${limit.windowSeconds} seconds.`, flags: MessageFlags.Ephemeral });
      return;
    }
    const policy = await kernel.policies.context(guildId);
    const guild = await kernel.deps.gateway.getGuild(guildId);
    if (!guild) {
      await interaction.reply({ content: "The server is unavailable right now.", flags: MessageFlags.Ephemeral });
      return;
    }
    const access = resolveAccess(policy, guild, userId, [...interaction.member.roles.cache.keys()]);
    const required = REQUIRED_ACCESS[name] ?? "owner";
    const context: CommandContext = { interaction, name, guildId, userId, access, policy, guild, deps: this.deps };
    if (!hasAccess(access, required)) {
      await kernel.honeypot.signal({ guildId, userId, kind: "unauthorized-command", context: { command: name, required, access } });
      await interaction.reply({ content: `This command requires the ${required} access level in Val Protection's policy.`, flags: MessageFlags.Ephemeral });
      return;
    }
    if (name === "panel") {
      try {
        await this.panel.open(interaction, access);
      } catch (error) {
        logger.error({ err: errorMessage(error), guildId }, "Panel failed to open");
        if (interaction.deferred) await interaction.editReply({ content: "The panel could not be opened; check the bot logs." }).catch(() => undefined);
      }
      return;
    }
    const handler = HANDLERS[name];
    if (!handler) {
      await interaction.reply({ content: "Unknown subcommand.", flags: MessageFlags.Ephemeral });
      return;
    }
    try {
      await handler(context);
    } catch (error) {
      logger.error({ err: errorMessage(error), command: name, guildId }, "Command failed");
      await kernel.evidence.append({ guildId, eventType: "command.error", severity: "low", actorId: userId, evidence: { command: name }, error: errorMessage(error) });
      const message = { content: "The command failed. The error was logged; check the bot logs." };
      if (interaction.deferred || interaction.replied) await interaction.editReply({ ...message, embeds: [], components: [] }).catch(() => undefined);
      else await interaction.reply({ ...message, flags: MessageFlags.Ephemeral }).catch(() => undefined);
    }
  }

  private async handleAutocomplete(interaction: AutocompleteInteraction): Promise<void> {
    if (interaction.commandName !== COMMAND_NAME || !interaction.inCachedGuild()) {
      await interaction.respond([]).catch(() => undefined);
      return;
    }
    const focused = interaction.options.getFocused(true);
    await interaction.respond(focused.name === "key" ? configAutocomplete(String(focused.value)) : []).catch(() => undefined);
  }

  private async handleButton(interaction: ButtonInteraction): Promise<void> {
    const { kernel, confirmations, logger } = this.deps;
    const lookup = confirmations.consume(interaction.customId, interaction.guildId, interaction.user.id);
    if (lookup.status === "unknown") {
      await interaction.reply({ content: "This confirmation is unknown, expired or already used.", flags: MessageFlags.Ephemeral });
      return;
    }
    if (lookup.status === "foreign") {
      await kernel.honeypot.signal({ guildId: lookup.pending.guildId, userId: interaction.user.id, kind: "foreign-confirmation", context: { action: lookup.pending.action, owner: lookup.pending.userId } });
      await interaction.reply({ content: "This confirmation belongs to someone else.", flags: MessageFlags.Ephemeral });
      return;
    }
    if (lookup.status === "expired") {
      await interaction.update({ content: "Confirmation expired. Run the command again.", embeds: [], components: [] });
      return;
    }
    if (!lookup.confirmed) {
      await interaction.update({ content: "Cancelled.", embeds: [], components: [] });
      return;
    }
    const pending = lookup.pending;
    const policy = await kernel.policies.context(pending.guildId);
    const guild = await kernel.deps.gateway.getGuild(pending.guildId);
    const roleIds = interaction.inCachedGuild() ? [...interaction.member.roles.cache.keys()] : [];
    if (!guild || !hasAccess(resolveAccess(policy, guild, interaction.user.id, roleIds), pending.requiredAccess)) {
      await interaction.update({ content: "Your access level changed; the action was not executed.", embeds: [], components: [] });
      return;
    }
    await interaction.deferUpdate();
    try {
      const result = await pending.execute();
      await interaction.editReply({ content: result.slice(0, 1900), embeds: [], components: [] });
    } catch (error) {
      logger.error({ err: errorMessage(error), action: pending.action }, "Confirmed action failed");
      await interaction.editReply({ content: "The action failed. The error was logged.", embeds: [], components: [] });
    }
  }
}
