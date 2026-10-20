import { InteractionContextType, PermissionFlagsBits, SlashCommandBuilder, type RESTPostAPIChatInputApplicationCommandsJSONBody } from "discord.js";
import { WHITELIST_SCOPES } from "../core/types.js";
import { SCENARIOS } from "../simulation/ruleTester.js";
import type { AccessLevel } from "../security/policy/authorization.js";

export const COMMAND_NAME = "security";

export const REQUIRED_ACCESS: Record<string, AccessLevel> = {
  panel: "auditor",
  status: "auditor",
  scan: "securityAdmin",
  lockdown: "securityAdmin",
  unlock: "securityAdmin",
  logs: "auditor",
  config: "auditor",
  "whitelist add": "securityAdmin",
  "whitelist remove": "securityAdmin",
  roles: "auditor",
  "protect-role": "securityAdmin",
  incident: "auditor",
  test: "securityAdmin",
  "backup-status": "auditor",
  recover: "securityAdmin"
};

export function buildSecurityCommand(): RESTPostAPIChatInputApplicationCommandsJSONBody {
  return new SlashCommandBuilder()
    .setName(COMMAND_NAME)
    .setDescription("Val Protection security controls")
    .setDefaultMemberPermissions(PermissionFlagsBits.ManageGuild)
    .setContexts(InteractionContextType.Guild)
    .addSubcommand((sub) => sub.setName("panel").setDescription("Open the configuration panel"))
    .addSubcommand((sub) => sub.setName("status").setDescription("Show the overall protection status"))
    .addSubcommand((sub) => sub.setName("scan").setDescription("Analyse roles, permissions, hierarchy and configuration"))
    .addSubcommand((sub) =>
      sub
        .setName("lockdown")
        .setDescription("Activate lockdown mode")
        .addStringOption((option) => option.setName("reason").setDescription("Why lockdown is needed").setRequired(true).setMinLength(3).setMaxLength(300))
        .addIntegerOption((option) => option.setName("minutes").setDescription("Duration before automatic expiry").setMinValue(5).setMaxValue(1440))
    )
    .addSubcommand((sub) =>
      sub
        .setName("unlock")
        .setDescription("End lockdown mode after confirmation")
        .addStringOption((option) => option.setName("reason").setDescription("Why lockdown can end").setRequired(true).setMinLength(3).setMaxLength(300))
    )
    .addSubcommand((sub) =>
      sub
        .setName("logs")
        .setDescription("Review recent incidents or evidence records")
        .addStringOption((option) =>
          option
            .setName("source")
            .setDescription("What to list")
            .addChoices({ name: "incidents", value: "incidents" }, { name: "evidence events", value: "events" }, { name: "verify integrity", value: "verify" })
        )
        .addStringOption((option) =>
          option
            .setName("severity")
            .setDescription("Minimum severity")
            .addChoices(
              { name: "all", value: "info" },
              { name: "low", value: "low" },
              { name: "medium", value: "medium" },
              { name: "high", value: "high" },
              { name: "critical", value: "critical" }
            )
        )
        .addIntegerOption((option) => option.setName("limit").setDescription("Number of entries").setMinValue(1).setMaxValue(25))
    )
    .addSubcommand((sub) =>
      sub
        .setName("config")
        .setDescription("Show or change runtime-editable settings")
        .addStringOption((option) => option.setName("key").setDescription("Setting to show or change (start typing)").setAutocomplete(true).setMaxLength(80))
        .addStringOption((option) => option.setName("value").setDescription("New value").setMinLength(1).setMaxLength(64))
    )
    .addSubcommandGroup((group) =>
      group
        .setName("whitelist")
        .setDescription("Manage approved people and bots")
        .addSubcommand((sub) =>
          sub
            .setName("add")
            .setDescription("Approve a person or bot for a scope")
            .addUserOption((option) => option.setName("target").setDescription("Person or bot").setRequired(true))
            .addStringOption((option) =>
              option
                .setName("scope")
                .setDescription("What the approval covers")
                .setRequired(true)
                .addChoices(...WHITELIST_SCOPES.map((scope) => ({ name: scope, value: scope })))
            )
            .addStringOption((option) => option.setName("reason").setDescription("Justification").setRequired(true).setMinLength(3).setMaxLength(300))
            .addIntegerOption((option) => option.setName("hours").setDescription("Expire after this many hours").setMinValue(1).setMaxValue(720))
        )
        .addSubcommand((sub) =>
          sub
            .setName("remove")
            .setDescription("Revoke every approval of a person or bot")
            .addUserOption((option) => option.setName("target").setDescription("Person or bot").setRequired(true))
            .addStringOption((option) => option.setName("reason").setDescription("Justification").setRequired(true).setMinLength(3).setMaxLength(300))
        )
    )
    .addSubcommand((sub) => sub.setName("roles").setDescription("List sensitive and protected roles"))
    .addSubcommand((sub) =>
      sub
        .setName("protect-role")
        .setDescription("Protect or unprotect a role and define who may grant it")
        .addRoleOption((option) => option.setName("role").setDescription("Role").setRequired(true))
        .addStringOption((option) =>
          option.setName("action").setDescription("Protect or unprotect").setRequired(true).addChoices({ name: "protect", value: "protect" }, { name: "unprotect", value: "unprotect" })
        )
        .addUserOption((option) => option.setName("granter").setDescription("Person allowed to grant this role"))
        .addRoleOption((option) => option.setName("granter-role").setDescription("Role whose holders may grant this role"))
    )
    .addSubcommand((sub) =>
      sub
        .setName("incident")
        .setDescription("Show the details of an incident")
        .addStringOption((option) => option.setName("id").setDescription("Incident ID such as INC-1A2B3C4D5E").setRequired(true).setMinLength(6).setMaxLength(20))
    )
    .addSubcommand((sub) =>
      sub
        .setName("test")
        .setDescription("Simulate attacks against your rules without touching the server")
        .addStringOption((option) =>
          option
            .setName("scenario")
            .setDescription("Scenario to simulate")
            .addChoices({ name: "all", value: "all" }, ...SCENARIOS.map((scenario) => ({ name: scenario, value: scenario })))
        )
    )
    .addSubcommand((sub) => sub.setName("backup-status").setDescription("Show structural snapshots, database backups and log integrity"))
    .addSubcommand((sub) =>
      sub
        .setName("recover")
        .setDescription("Recreate missing roles and channels from a snapshot after confirmation")
        .addStringOption((option) => option.setName("snapshot").setDescription("Snapshot ID (latest by default)").setMinLength(6).setMaxLength(20))
    )
    .toJSON();
}
