import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ChannelSelectMenuBuilder,
  ChannelType,
  RoleSelectMenuBuilder,
  StringSelectMenuBuilder,
  UserSelectMenuBuilder,
  type APIEmbed,
  type APIEmbedField,
  type MessageActionRowComponentBuilder
} from "discord.js";
import { describeValue, getSetting, type SectionId, type SettingDefinition } from "../../config/settings.js";
import { ACTION_CATEGORIES } from "../../core/types.js";
import type { ProtectedRoleRecord } from "../../database/repositories/protectedRoleRepository.js";
import type { RoleInfo } from "../../discord/gateway.js";
import { SEVERITY_COLOR } from "../../security/alerts/format.js";
import { hasAccess, type AccessLevel } from "../../security/policy/authorization.js";
import type { PolicyContext } from "../../security/policy/policyService.js";
import { customId, type PanelSession, type PanelView } from "./sessions.js";

export interface RenderInput {
  session: PanelSession;
  context: PolicyContext;
  access: AccessLevel;
  guildName: string;
  roles: RoleInfo[];
  tableRoles: ProtectedRoleRecord[];
  memberNames: Map<string, string>;
  lockdownActive: boolean;
  value: (path: string) => unknown;
}

export interface RenderedPanel {
  embeds: APIEmbed[];
  components: Array<ActionRowBuilder<MessageActionRowComponentBuilder>>;
}

type Row = ActionRowBuilder<MessageActionRowComponentBuilder>;

export const SECTIONS: ReadonlyArray<{ id: SectionId | "whitelist"; label: string; description: string }> = [
  { id: "general", label: "General", description: "Mode, alert channel, alert ping role" },
  { id: "access", label: "Access", description: "Security administrators, auditors, staff roles" },
  { id: "raid", label: "Anti-raid", description: "Quarantine role, measures, join thresholds" },
  { id: "nuke", label: "Anti-nuke", description: "Thresholds per action, response, lockdown" },
  { id: "roles", label: "Role protection", description: "Protected roles and who may grant them" },
  { id: "bots", label: "Bots and webhooks", description: "Approved bots, who may add bots or webhooks" },
  { id: "spam", label: "Anti-spam", description: "Exemptions, limits, link rules" },
  { id: "honeypot", label: "Honeypot", description: "Decoy roles and channels, traps" },
  { id: "lockdown", label: "Lockdown and retention", description: "Lockdown actions, durations, snapshots" },
  { id: "whitelist", label: "Whitelist", description: "Approved people and bots with scopes" }
];

const MAX_SELECT = 25;

function row(...components: MessageActionRowComponentBuilder[]): Row {
  return new ActionRowBuilder<MessageActionRowComponentBuilder>().addComponents(...components);
}

function canEdit(input: RenderInput, definition?: SettingDefinition): boolean {
  if (!hasAccess(input.access, "securityAdmin")) return false;
  if (definition?.ownerOnly) return input.access === "owner";
  return true;
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function field(input: RenderInput, path: string, inline = true): APIEmbedField {
  const definition = getSetting(path);
  return { name: clip(definition.label, 256), value: clip(describeValue(definition, input.value(path)), 1024), inline };
}

function toggle(input: RenderInput, path: string, labelOverride?: string): ButtonBuilder {
  const definition = getSetting(path);
  const on = input.value(path) === true;
  return new ButtonBuilder()
    .setCustomId(customId(input.session, "tog", path))
    .setLabel(clip(`${labelOverride ?? definition.label}: ${on ? "on" : "off"}`, 80))
    .setStyle(on ? ButtonStyle.Success : ButtonStyle.Secondary)
    .setDisabled(!canEdit(input, definition));
}

function cycle(input: RenderInput, path: string): ButtonBuilder {
  const definition = getSetting(path);
  return new ButtonBuilder()
    .setCustomId(customId(input.session, "cyc", path))
    .setLabel(clip(`${definition.label}: ${String(input.value(path))}`, 80))
    .setStyle(ButtonStyle.Primary)
    .setDisabled(!canEdit(input, definition));
}

function modalButton(input: RenderInput, group: string, label: string): ButtonBuilder {
  return new ButtonBuilder().setCustomId(customId(input.session, "mod", group)).setLabel(label).setStyle(ButtonStyle.Secondary).setDisabled(!canEdit(input));
}

function nav(input: RenderInput, view: PanelView, label: string, style = ButtonStyle.Secondary): ButtonBuilder {
  return new ButtonBuilder().setCustomId(customId(input.session, "nav", view)).setLabel(label).setStyle(style);
}

function back(input: RenderInput, view: PanelView = "home"): ButtonBuilder {
  return nav(input, view, view === "home" ? "Back" : "Back to roles");
}

function idList(input: RenderInput, path: string): string[] {
  const value = input.value(path);
  return Array.isArray(value) ? value.map(String) : [];
}

function tooLong(ids: readonly string[]): boolean {
  return ids.length > MAX_SELECT;
}

function userSelect(input: RenderInput, path: string, placeholder: string): UserSelectMenuBuilder {
  const definition = getSetting(path);
  const ids = idList(input, path);
  const menu = new UserSelectMenuBuilder()
    .setCustomId(customId(input.session, "set", path))
    .setPlaceholder(clip(placeholder, 150))
    .setMinValues(0)
    .setMaxValues(MAX_SELECT)
    .setDisabled(!canEdit(input, definition) || tooLong(ids));
  if (ids.length > 0 && !tooLong(ids)) menu.setDefaultUsers(...ids);
  return menu;
}

function roleSelect(input: RenderInput, path: string, placeholder: string, single = false): RoleSelectMenuBuilder {
  const definition = getSetting(path);
  const value = input.value(path);
  const ids = single ? (typeof value === "string" ? [value] : []) : idList(input, path);
  const menu = new RoleSelectMenuBuilder()
    .setCustomId(customId(input.session, "set", path))
    .setPlaceholder(clip(placeholder, 150))
    .setMinValues(0)
    .setMaxValues(single ? 1 : MAX_SELECT)
    .setDisabled(!canEdit(input, definition) || tooLong(ids));
  if (ids.length > 0 && !tooLong(ids)) menu.setDefaultRoles(...ids);
  return menu;
}

const TEXT_CHANNELS = [ChannelType.GuildText, ChannelType.GuildAnnouncement] as const;
const MESSAGE_CHANNELS = [ChannelType.GuildText, ChannelType.GuildAnnouncement, ChannelType.GuildForum, ChannelType.GuildVoice, ChannelType.GuildStageVoice, ChannelType.GuildMedia] as const;

function channelSelect(input: RenderInput, path: string, placeholder: string, single = false): ChannelSelectMenuBuilder {
  const definition = getSetting(path);
  const value = input.value(path);
  const ids = single ? (typeof value === "string" ? [value] : []) : idList(input, path);
  const menu = new ChannelSelectMenuBuilder()
    .setCustomId(customId(input.session, "set", path))
    .setPlaceholder(clip(placeholder, 150))
    .setChannelTypes(...(single ? TEXT_CHANNELS : MESSAGE_CHANNELS))
    .setMinValues(0)
    .setMaxValues(single ? 1 : MAX_SELECT)
    .setDisabled(!canEdit(input, definition) || tooLong(ids));
  if (ids.length > 0 && !tooLong(ids)) menu.setDefaultChannels(...ids);
  return menu;
}

function enumSelect(input: RenderInput, path: string, labels: Record<string, string>): StringSelectMenuBuilder {
  const definition = getSetting(path);
  if (definition.kind.type !== "enum") throw new Error(`${path} is not an enum`);
  const current = String(input.value(path));
  return new StringSelectMenuBuilder()
    .setCustomId(customId(input.session, "set", path))
    .setPlaceholder(clip(definition.label, 150))
    .setMinValues(1)
    .setMaxValues(1)
    .setDisabled(!canEdit(input, definition))
    .addOptions(
      definition.kind.values.map((value) => ({
        label: clip(`${definition.label}: ${labels[value] ?? value}`, 100),
        value,
        default: value === current
      }))
    );
}

function embed(input: RenderInput, title: string, description: string, fields: APIEmbedField[] = []): APIEmbed {
  const notice = input.session.notice ? `${input.session.notice.ok ? "✅" : "⛔"} ${input.session.notice.text}\n\n` : "";
  const readOnly = hasAccess(input.access, "securityAdmin") ? "" : "\n\n🔒 Read-only: you have the auditor access level.";
  return {
    title: clip(`Val Protection • ${title}`, 256),
    description: clip(`${notice}${description}${readOnly}`, 4000),
    color: input.session.notice && !input.session.notice.ok ? SEVERITY_COLOR.high : input.lockdownActive ? SEVERITY_COLOR.medium : SEVERITY_COLOR.low,
    fields: fields.slice(0, 25),
    footer: { text: clip(`${input.guildName} • panel closes after 30 minutes of inactivity`, 2048) }
  };
}

function checklist(input: RenderInput): string[] {
  const missing: string[] = [];
  if (!input.value("alertChannelId")) missing.push("Choose an alert channel (General)");
  if (idList(input, "securityAdminIds").length === 0) missing.push("Add security administrators (Access), otherwise only the owner can manage Val Protection");
  if (!input.value("antiRaid.quarantineRoleId")) missing.push("Choose a quarantine role without permissions (Anti-raid)");
  if (input.value("mode") === "monitor") missing.push("Switch Mode to automatic once alerts look right (General)");
  return missing;
}

function home(input: RenderInput): RenderedPanel {
  const todo = checklist(input);
  const protections = ["antiRaid.enabled", "antiNuke.enabled", "roleProtection.enabled", "antiSpam.enabled", "honeypot.enabled"]
    .map((path) => `${input.value(path) === true ? "🟢" : "🔴"} ${getSetting(path).label}`)
    .join("\n");
  const fields: APIEmbedField[] = [
    field(input, "mode"),
    field(input, "alertChannelId"),
    { name: "Lockdown", value: input.lockdownActive ? "ACTIVE" : "inactive", inline: true },
    { name: "Protections", value: protections, inline: true },
    field(input, "securityAdminIds", false)
  ];
  if (todo.length > 0) fields.push({ name: "Setup checklist", value: clip(todo.map((item) => `• ${item}`).join("\n"), 1024), inline: false });
  const select = new StringSelectMenuBuilder()
    .setCustomId(customId(input.session, "nav"))
    .setPlaceholder("Open a section…")
    .addOptions(SECTIONS.map((section) => ({ label: section.label, value: section.id, description: clip(section.description, 100) })));
  return {
    embeds: [embed(input, "Control panel", "Every setting below applies to this server only. Changes are validated, recorded in the evidence log and announced in the alert channel. Changes that weaken protection ask for confirmation.", fields)],
    components: [
      row(select),
      row(
        new ButtonBuilder().setCustomId(customId(input.session, "refresh")).setLabel("Refresh").setStyle(ButtonStyle.Secondary),
        new ButtonBuilder().setCustomId(customId(input.session, "close")).setLabel("Close").setStyle(ButtonStyle.Danger)
      )
    ]
  };
}

function general(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(input, "General", "**Mode**: `monitor` only alerts and records; `automatic` also responds. The alert channel must be private to the security team.", [
        field(input, "mode"),
        field(input, "alertChannelId"),
        field(input, "alertPingRoleId"),
        field(input, "weakeningChangesRequireOwner")
      ])
    ],
    components: [
      row(channelSelect(input, "alertChannelId", "Alert channel (private)", true)),
      row(roleSelect(input, "alertPingRoleId", "Role pinged on high and critical alerts (optional)", true)),
      row(
        cycle(input, "mode"),
        toggle(input, "weakeningChangesRequireOwner", "Owner approval to weaken"),
        new ButtonBuilder().setCustomId(customId(input.session, "test")).setLabel("Send test alert").setStyle(ButtonStyle.Secondary).setDisabled(!canEdit(input)),
        back(input)
      )
    ]
  };
}

function access(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(
        input,
        "Access",
        "**Security administrators** manage Val Protection. **Auditors** can read status, logs and this panel. **Staff roles** are exempt from anti-spam and never timed out by the honeypot. Only the server owner can change administrators and auditors.",
        [field(input, "securityAdminIds", false), field(input, "auditorRoleIds", false), field(input, "staffRoleIds", false)]
      )
    ],
    components: [
      row(userSelect(input, "securityAdminIds", "Security administrators (owner only)")),
      row(roleSelect(input, "auditorRoleIds", "Auditor roles (owner only)")),
      row(roleSelect(input, "staffRoleIds", "Staff roles")),
      row(back(input))
    ]
  };
}

function raid(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(input, "Anti-raid", "Joins are scored (account age, avatar, name and creation clusters, rejoins, spammer flag). Val Protection never bans; suspects are quarantined, timed out, or kicked only above the kick score during a confirmed raid.", [
        field(input, "antiRaid.quarantineRoleId"),
        field(input, "antiRaid.suspectAction"),
        field(input, "antiRaid.minJoinsForRaid"),
        field(input, "antiRaid.windowSeconds"),
        field(input, "antiRaid.raidScoreThreshold"),
        field(input, "antiRaid.suspectScoreThreshold"),
        field(input, "antiRaid.newAccountDays"),
        field(input, "antiRaid.kickMinScore"),
        field(input, "antiRaid.timeoutMinutes")
      ])
    ],
    components: [
      row(roleSelect(input, "antiRaid.quarantineRoleId", "Quarantine role (no permissions, below Val Protection)", true)),
      row(enumSelect(input, "antiRaid.suspectAction", { none: "log only", quarantine: "quarantine", timeout: "timeout", kick: "kick (only during raids)" })),
      row(
        toggle(input, "antiRaid.enabled"),
        toggle(input, "antiRaid.autoLockdown"),
        toggle(input, "antiRaid.actOnlyDuringRaid", "Only during raids"),
        modalButton(input, "raidThresholds", "Thresholds…"),
        modalButton(input, "raidMeasures", "Measures…")
      ),
      row(back(input))
    ]
  };
}

function nuke(input: RenderInput): RenderedPanel {
  const thresholds = ACTION_CATEGORIES.map((category) => `\`${category}\` ${String(input.value(`antiNuke.thresholds.${category}.limit`))} / ${String(input.value(`antiNuke.thresholds.${category}.windowSeconds`))}s`);
  const select = new StringSelectMenuBuilder()
    .setCustomId(customId(input.session, "nukecat"))
    .setPlaceholder("Edit the threshold of an action…")
    .setDisabled(!canEdit(input))
    .addOptions(
      ACTION_CATEGORIES.map((category) => ({
        label: clip(`${category}: ${String(input.value(`antiNuke.thresholds.${category}.limit`))} in ${String(input.value(`antiNuke.thresholds.${category}.windowSeconds`))}s`, 100),
        value: category
      }))
    );
  return {
    embeds: [
      embed(input, "Anti-nuke", "When one account performs more than **limit** actions of a kind within the window, Val Protection removes only the roles that grant that permission (or kicks a bot). Thresholds are halved during lockdown.", [
        field(input, "antiNuke.response"),
        field(input, "antiNuke.minConfidenceToContain"),
        field(input, "antiNuke.autoLockdownOnSeverity"),
        { name: "Thresholds (limit / window)", value: clip(thresholds.join("\n"), 1024), inline: false }
      ])
    ],
    components: [
      row(select),
      row(enumSelect(input, "antiNuke.autoLockdownOnSeverity", { never: "never", high: "high and critical incidents", critical: "critical incidents only" })),
      row(toggle(input, "antiNuke.enabled"), cycle(input, "antiNuke.response"), cycle(input, "antiNuke.minConfidenceToContain"), toggle(input, "antiNuke.containBotsByKick"), back(input))
    ]
  };
}

function rolesView(input: RenderInput): RenderedPanel {
  const tableIds = input.tableRoles.map((record) => record.roleId);
  const fileIds = [...input.context.protectedRoles.values()].filter((rule) => rule.source === "config").map((rule) => rule.roleId);
  const roleName = new Map(input.roles.map((role) => [role.id, role.name]));
  const protectedSelect = new RoleSelectMenuBuilder()
    .setCustomId(customId(input.session, "prot"))
    .setPlaceholder("Protected roles")
    .setMinValues(0)
    .setMaxValues(MAX_SELECT)
    .setDisabled(!canEdit(input) || tooLong(tableIds));
  if (tableIds.length > 0 && !tooLong(tableIds)) protectedSelect.setDefaultRoles(...tableIds);
  const components: Row[] = [row(protectedSelect), row(userSelect(input, "roleProtection.authorizedGranterIds", "People allowed to grant every protected role"))];
  const editable = [...input.context.protectedRoles.keys()].slice(0, MAX_SELECT);
  if (editable.length > 0) {
    components.push(
      row(
        new StringSelectMenuBuilder()
          .setCustomId(customId(input.session, "gsel"))
          .setPlaceholder("Choose who may grant a specific protected role…")
          .setDisabled(!canEdit(input))
          .addOptions(editable.map((roleId) => ({ label: clip(roleName.get(roleId) ?? roleId, 100), value: roleId })))
      )
    );
  }
  components.push(
    row(
      toggle(input, "roleProtection.enabled"),
      toggle(input, "roleProtection.treatDangerousRolesAsProtected", "All dangerous roles"),
      toggle(input, "roleProtection.revokeFromRecipient", "Revoke grants"),
      toggle(input, "roleProtection.revertUnauthorizedPermissionChanges", "Revert escalations"),
      cycle(input, "roleProtection.granterResponse")
    ),
    row(back(input))
  );
  return {
    embeds: [
      embed(
        input,
        "Role protection",
        "A sensitive role granted by someone the policy does not allow is revoked, and the granter loses only their role-management access. Roles carrying dangerous permissions are protected automatically when **All dangerous roles** is on. The owner and security administrators can always grant.",
        [
          { name: "Protected roles", value: clip(tableIds.map((id) => `<@&${id}>`).join(", ") || "none", 1024), inline: false },
          ...(fileIds.length > 0 ? [{ name: "Protected by the configuration file", value: clip(fileIds.map((id) => `<@&${id}>`).join(", "), 1024), inline: false }] : []),
          field(input, "roleProtection.authorizedGranterIds", false),
          field(input, "roleProtection.granterResponse")
        ]
      )
    ],
    components
  };
}

function granters(input: RenderInput): RenderedPanel {
  const roleId = input.session.grantersRoleId;
  const rule = roleId ? input.context.protectedRoles.get(roleId) : undefined;
  if (!roleId || !rule) {
    return { embeds: [embed(input, "Granters", "This role is no longer protected.")], components: [row(back(input, "roles"))] };
  }
  const users = new UserSelectMenuBuilder()
    .setCustomId(customId(input.session, "gu", roleId))
    .setPlaceholder("People allowed to grant this role")
    .setMinValues(0)
    .setMaxValues(MAX_SELECT)
    .setDisabled(!canEdit(input));
  if (rule.allowedGranterIds.length > 0) users.setDefaultUsers(...rule.allowedGranterIds.slice(0, MAX_SELECT));
  const roles = new RoleSelectMenuBuilder()
    .setCustomId(customId(input.session, "gr", roleId))
    .setPlaceholder("Roles whose members may grant this role")
    .setMinValues(0)
    .setMaxValues(MAX_SELECT)
    .setDisabled(!canEdit(input));
  if (rule.allowedGranterRoleIds.length > 0) roles.setDefaultRoles(...rule.allowedGranterRoleIds.slice(0, MAX_SELECT));
  return {
    embeds: [
      embed(input, "Granters", `Who may grant <@&${roleId}> besides the owner and security administrators.`, [
        { name: "People", value: clip(rule.allowedGranterIds.map((id) => `<@${id}>`).join(", ") || "none", 1024), inline: false },
        { name: "Roles", value: clip(rule.allowedGranterRoleIds.map((id) => `<@&${id}>`).join(", ") || "none", 1024), inline: false }
      ])
    ],
    components: [row(users), row(roles), row(back(input, "roles"))]
  };
}

function bots(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(input, "Bots and webhooks", "Bots that are not approved are placed in logical quarantine and reported; not being approved never means malicious. Webhooks created by people outside the managers list are reported or deleted.", [
        field(input, "bots.approvedBotIds", false),
        field(input, "bots.authorizedAdderIds", false),
        field(input, "integrations.authorizedManagerIds", false),
        field(input, "bots.unapprovedAction"),
        field(input, "integrations.unauthorizedWebhookAction")
      ])
    ],
    components: [
      row(userSelect(input, "bots.approvedBotIds", "Approved bots")),
      row(userSelect(input, "bots.authorizedAdderIds", "People allowed to add bots")),
      row(userSelect(input, "integrations.authorizedManagerIds", "People allowed to manage webhooks and integrations")),
      row(cycle(input, "bots.unapprovedAction"), toggle(input, "bots.kickOnlyWhenAdderUnauthorized", "Kick only if adder unauthorized"), cycle(input, "integrations.unauthorizedWebhookAction"), back(input))
    ]
  };
}

function spam(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(input, "Anti-spam", "Progressive response: warning, deletion, then timeout. Staff roles and members with Manage Messages are always exempt.", [
        field(input, "antiSpam.exemptRoleIds", false),
        field(input, "antiSpam.exemptChannelIds", false),
        field(input, "antiSpam.burst.maxMessages"),
        field(input, "antiSpam.burst.windowSeconds"),
        field(input, "antiSpam.duplicates.max"),
        field(input, "antiSpam.maxMentions"),
        field(input, "antiSpam.timeoutMinutes"),
        field(input, "antiSpam.links.blockedDomains", false),
        field(input, "antiSpam.links.allowedDomains", false)
      ])
    ],
    components: [
      row(roleSelect(input, "antiSpam.exemptRoleIds", "Exempt roles")),
      row(channelSelect(input, "antiSpam.exemptChannelIds", "Exempt channels")),
      row(toggle(input, "antiSpam.enabled"), modalButton(input, "spamLimits", "Limits…"), modalButton(input, "spamDomains", "Domains…"), toggle(input, "antiSpam.floodSlowmode.enabled"), back(input)),
      row(
        toggle(input, "antiSpam.links.flagInvites"),
        toggle(input, "antiSpam.links.flagShorteners"),
        toggle(input, "antiSpam.links.flagLookalikes"),
        toggle(input, "antiSpam.links.flagIpHosts")
      )
    ]
  };
}

function honeypot(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(input, "Honeypot", "Decoys are passive and harmless: decoy roles must have no permission. Interactions are correlated over time to tell honest mistakes from malicious behaviour.", [
        field(input, "honeypot.decoyRoleIds", false),
        field(input, "honeypot.decoyChannelIds", false),
        field(input, "honeypot.escalationAction"),
        field(input, "honeypot.forbiddenCommandPatterns", false)
      ])
    ],
    components: [
      row(roleSelect(input, "honeypot.decoyRoleIds", "Decoy roles (no permissions)")),
      row(channelSelect(input, "honeypot.decoyChannelIds", "Decoy channels")),
      row(toggle(input, "honeypot.enabled"), cycle(input, "honeypot.escalationAction"), modalButton(input, "honeypotPatterns", "Forbidden commands…"), back(input))
    ]
  };
}

function lockdown(input: RenderInput): RenderedPanel {
  return {
    embeds: [
      embed(input, "Lockdown and retention", "Lockdown only uses what Discord allows: verification level, invite pause, quarantine of newcomers, stricter thresholds. It always expires and never removes administrators' capabilities.", [
        field(input, "lockdown.verificationLevel"),
        field(input, "lockdown.maxDurationMinutes"),
        field(input, "logging.retentionDays"),
        field(input, "backups.intervalMinutes"),
        field(input, "backups.keep")
      ])
    ],
    components: [
      row(enumSelect(input, "lockdown.verificationLevel", { Medium: "Medium", High: "High", VeryHigh: "Very high (phone required)" })),
      row(
        toggle(input, "lockdown.raiseVerificationLevel"),
        toggle(input, "lockdown.pauseInvites"),
        toggle(input, "lockdown.quarantineNewMembers"),
        toggle(input, "lockdown.restrictProtectedRoleGrants"),
        toggle(input, "lockdown.suspendNonEssential")
      ),
      row(modalButton(input, "durations", "Durations and retention…"), toggle(input, "backups.enabled"), back(input))
    ]
  };
}

function whitelist(input: RenderInput): RenderedPanel {
  const entries = input.context.whitelist;
  const lines = entries.map((entry) => `<@${entry.subjectId}> • \`${entry.scopes.join(", ")}\` • ${entry.expiresAt ? `until <t:${Math.floor(Date.parse(entry.expiresAt) / 1000)}:R>` : "no expiry"} • ${entry.reason}`);
  const components: Row[] = [];
  const subjects = [...new Set(entries.map((entry) => entry.subjectId))].slice(0, MAX_SELECT);
  if (subjects.length > 0) {
    components.push(
      row(
        new StringSelectMenuBuilder()
          .setCustomId(customId(input.session, "wlrev"))
          .setPlaceholder("Revoke approvals…")
          .setMinValues(1)
          .setMaxValues(subjects.length)
          .setDisabled(!canEdit(input))
          .addOptions(
            subjects.map((subjectId) => ({
              label: clip(input.memberNames.get(subjectId) ?? subjectId, 100),
              value: subjectId,
              description: clip(entries.filter((entry) => entry.subjectId === subjectId).map((entry) => entry.scopes.join(",")).join(" | "), 100)
            }))
          )
      )
    );
  }
  components.push(row(new ButtonBuilder().setCustomId(customId(input.session, "mod", "wladd")).setLabel("Approve someone…").setStyle(ButtonStyle.Primary).setDisabled(!canEdit(input)), back(input)));
  return {
    embeds: [embed(input, "Whitelist", `Approved accounts are exempt from automatic containment in their scope; everything they do is still logged.\n\n${clip(lines.join("\n") || "No active approval.", 3000)}`)],
    components
  };
}

function confirm(input: RenderInput): RenderedPanel {
  const plan = input.session.pending;
  if (!plan) return home(input);
  const lines = plan.changes.map((change) => `${change.weakening ? "⚠ " : ""}**${change.label}**: ${change.previous} → ${change.next}`);
  return {
    embeds: [
      {
        title: "Val Protection • Confirm change",
        color: SEVERITY_COLOR.high,
        description: clip(
          [
            ...lines,
            "",
            plan.weakening ? "This change **weakens** protection. It will be recorded and announced as such." : "Please confirm this change.",
            ...plan.notes.map((note) => `• ${note}`)
          ].join("\n"),
          4000
        )
      }
    ],
    components: [
      row(
        new ButtonBuilder().setCustomId(customId(input.session, "ok")).setLabel("Confirm").setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId(customId(input.session, "cancel")).setLabel("Cancel").setStyle(ButtonStyle.Secondary)
      )
    ]
  };
}

export function renderPanel(input: RenderInput): RenderedPanel {
  if (input.session.pending) return confirm(input);
  switch (input.session.view) {
    case "home":
      return home(input);
    case "general":
      return general(input);
    case "access":
      return access(input);
    case "raid":
      return raid(input);
    case "nuke":
      return nuke(input);
    case "roles":
      return rolesView(input);
    case "granters":
      return granters(input);
    case "bots":
      return bots(input);
    case "spam":
      return spam(input);
    case "honeypot":
      return honeypot(input);
    case "lockdown":
      return lockdown(input);
    case "whitelist":
      return whitelist(input);
  }
}

export function isPanelView(value: string): value is PanelView {
  return value === "home" || value === "granters" || SECTIONS.some((section) => section.id === value);
}
