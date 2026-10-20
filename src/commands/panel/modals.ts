import { LabelBuilder, ModalBuilder, StringSelectMenuBuilder, TextInputBuilder, TextInputStyle, UserSelectMenuBuilder } from "discord.js";
import { getSetting } from "../../config/settings.js";
import { ACTION_CATEGORIES, WHITELIST_SCOPES, type ActionCategory } from "../../core/types.js";
import { customId, type PanelSession } from "./sessions.js";

export const NUMBER_GROUPS: Record<string, { title: string; paths: string[] }> = {
  raidThresholds: {
    title: "Anti-raid thresholds",
    paths: ["antiRaid.windowSeconds", "antiRaid.minJoinsForRaid", "antiRaid.raidScoreThreshold", "antiRaid.suspectScoreThreshold", "antiRaid.newAccountDays"]
  },
  raidMeasures: {
    title: "Anti-raid measures",
    paths: ["antiRaid.slowWaveWindowMinutes", "antiRaid.slowWaveSuspectCount", "antiRaid.timeoutMinutes", "antiRaid.kickMinScore", "antiRaid.raidCooldownMinutes"]
  },
  spamLimits: {
    title: "Anti-spam limits",
    paths: ["antiSpam.burst.maxMessages", "antiSpam.burst.windowSeconds", "antiSpam.duplicates.max", "antiSpam.maxMentions", "antiSpam.timeoutMinutes"]
  },
  durations: {
    title: "Durations and retention",
    paths: ["lockdown.maxDurationMinutes", "logging.retentionDays", "backups.intervalMinutes", "backups.keep"]
  }
};

export const LIST_GROUPS: Record<string, { title: string; paths: string[]; descriptions: Record<string, string> }> = {
  spamDomains: {
    title: "Link domains",
    paths: ["antiSpam.links.blockedDomains", "antiSpam.links.allowedDomains"],
    descriptions: {
      "antiSpam.links.blockedDomains": "One per line, e.g. scam.example or *.scam.example. Messages linking them are deleted.",
      "antiSpam.links.allowedDomains": "One per line. Links to these domains are never flagged."
    }
  },
  honeypotPatterns: {
    title: "Forbidden command traps",
    paths: ["honeypot.forbiddenCommandPatterns"],
    descriptions: { "honeypot.forbiddenCommandPatterns": "One per line, e.g. !nuke. A message starting with one is a trap signal." }
  }
};

export const MAX_TEXT = 4000;

function clip(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) : text;
}

function numberInput(path: string, value: unknown): LabelBuilder {
  const definition = getSetting(path);
  return new LabelBuilder()
    .setLabel(clip(definition.label, 45))
    .setTextInputComponent(
      new TextInputBuilder()
        .setCustomId(path)
        .setStyle(TextInputStyle.Short)
        .setRequired(true)
        .setMinLength(1)
        .setMaxLength(9)
        .setValue(String(value ?? ""))
    );
}

export function numberModal(session: PanelSession, group: string, value: (path: string) => unknown): ModalBuilder {
  const definition = NUMBER_GROUPS[group];
  if (!definition) throw new Error(`Unknown modal group ${group}`);
  return new ModalBuilder()
    .setCustomId(customId(session, "sub", group))
    .setTitle(definition.title)
    .addLabelComponents(...definition.paths.map((path) => numberInput(path, value(path))));
}

export function listModalText(value: unknown): string {
  return Array.isArray(value) ? value.map(String).join("\n") : "";
}

export function listModal(session: PanelSession, group: string, value: (path: string) => unknown): ModalBuilder {
  const definition = LIST_GROUPS[group];
  if (!definition) throw new Error(`Unknown modal group ${group}`);
  return new ModalBuilder()
    .setCustomId(customId(session, "sub", group))
    .setTitle(definition.title)
    .addLabelComponents(
      ...definition.paths.map((path) => {
        const input = new TextInputBuilder().setCustomId(path).setStyle(TextInputStyle.Paragraph).setRequired(false).setMaxLength(MAX_TEXT);
        const text = listModalText(value(path));
        if (text.length > 0) input.setValue(text);
        return new LabelBuilder()
          .setLabel(clip(getSetting(path).label, 45))
          .setDescription(clip(definition.descriptions[path] ?? "", 100))
          .setTextInputComponent(input);
      })
    );
}

export function isActionCategory(value: string): value is ActionCategory {
  return (ACTION_CATEGORIES as readonly string[]).includes(value);
}

export function nukeModal(session: PanelSession, category: ActionCategory, value: (path: string) => unknown): ModalBuilder {
  const limit = `antiNuke.thresholds.${category}.limit`;
  const window = `antiNuke.thresholds.${category}.windowSeconds`;
  return new ModalBuilder()
    .setCustomId(customId(session, "sub", `nuke:${category}`))
    .setTitle(clip(`Threshold: ${category}`, 45))
    .addLabelComponents(numberInput(limit, value(limit)), numberInput(window, value(window)));
}

const SCOPE_HELP: Record<string, string> = {
  all: "Every protection (owner only)",
  roles: "Role grants and role changes",
  channels: "Channel creation, deletion and overwrites",
  moderation: "Bans, kicks, prunes",
  webhooks: "Webhook management",
  bots: "Bot additions, integrations, command permissions",
  guild: "Server settings"
};

export function whitelistModal(session: PanelSession): ModalBuilder {
  return new ModalBuilder()
    .setCustomId(customId(session, "sub", "wladd"))
    .setTitle("Approve a person or bot")
    .addLabelComponents(
      new LabelBuilder()
        .setLabel("Person or bot")
        .setUserSelectMenuComponent(new UserSelectMenuBuilder().setCustomId("subject").setMinValues(1).setMaxValues(1)),
      new LabelBuilder()
        .setLabel("Scope")
        .setDescription("What the approval exempts from automatic containment")
        .setStringSelectMenuComponent(
          new StringSelectMenuBuilder()
            .setCustomId("scope")
            .setMinValues(1)
            .setMaxValues(1)
            .addOptions(WHITELIST_SCOPES.map((scope) => ({ label: scope, value: scope, description: SCOPE_HELP[scope] ?? scope })))
        ),
      new LabelBuilder()
        .setLabel("Reason")
        .setTextInputComponent(new TextInputBuilder().setCustomId("reason").setStyle(TextInputStyle.Short).setRequired(true).setMinLength(3).setMaxLength(300)),
      new LabelBuilder()
        .setLabel("Hours before expiry")
        .setDescription("Leave empty for no expiry (1 to 720)")
        .setTextInputComponent(new TextInputBuilder().setCustomId("hours").setStyle(TextInputStyle.Short).setRequired(false).setMaxLength(3))
    );
}
