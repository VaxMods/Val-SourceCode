import { SETTINGS, describeValue, getSetting, isScalar } from "../../config/settings.js";
import { ValidationError } from "../../core/errors.js";
import type { WhitelistScope } from "../../core/types.js";
import { SEVERITY_COLOR, sanitize } from "../../security/alerts/format.js";
import type { Actor, ChangeRequest } from "../../security/policy/settingsService.js";
import { respond, truncate, type CommandContext, type CommandHandler } from "../context.js";

function actorOf(context: CommandContext): Actor {
  return { userId: context.userId, access: context.access };
}

export async function planAndConfirm(context: CommandContext, requests: ChangeRequest[], title: string): Promise<void> {
  const outcome = await context.deps.kernel.settings.plan(context.guildId, actorOf(context), requests);
  if (!outcome.ok) {
    await respond(context, { content: outcome.error });
    return;
  }
  const plan = outcome.plan;
  const { row } = context.deps.confirmations.create({
    guildId: context.guildId,
    userId: context.userId,
    action: `settings:${plan.id}`,
    requiredAccess: plan.requiredAccess,
    execute: async () => {
      const result = await context.deps.kernel.settings.commit(actorOf(context), plan);
      return result.ok ? `Saved.\n${result.message}` : `Not saved: ${result.message}`;
    }
  });
  await respond(context, {
    embeds: [
      {
        title,
        color: plan.weakening ? SEVERITY_COLOR.high : SEVERITY_COLOR.medium,
        description: truncate(
          [
            ...plan.changes.map((change) => `${change.weakening ? "⚠ " : ""}**${change.label}**: ${change.previous} → ${change.next}`),
            plan.weakening ? "\nThis change **weakens** protection and will be reported as such." : "",
            ...plan.notes.map((note) => `• ${note}`),
            "\nConfirm within 60 seconds."
          ].join("\n"),
          4000
        )
      }
    ],
    components: [row]
  });
}

export const configHandler: CommandHandler = async (context) => {
  const key = context.interaction.options.getString("key");
  const value = context.interaction.options.getString("value");
  if (!key) {
    await respond(context, {
      content: "Use `/security panel` to see and change every setting with menus. `/security config key:<setting> value:<value>` changes a single value directly."
    });
    return;
  }
  let definition;
  try {
    definition = getSetting(key);
  } catch (error) {
    await respond(context, { content: error instanceof ValidationError ? error.message : "Unknown setting." });
    return;
  }
  const current = context.deps.kernel.policies.currentValue(context.policy, definition.path);
  if (value === null) {
    await respond(context, { content: `**${definition.label}** (\`${definition.path}\`) = ${describeValue(definition, current)}` });
    return;
  }
  if (!isScalar(definition)) {
    await respond(context, { content: `${definition.label} is a list; change it with \`/security panel\`.` });
    return;
  }
  await planAndConfirm(context, [{ kind: "setting", path: definition.path, value }], "Confirm configuration change");
};

export function configAutocomplete(query: string): Array<{ name: string; value: string }> {
  const needle = query.trim().toLowerCase();
  return [...SETTINGS.values()]
    .filter(isScalar)
    .filter((definition) => needle === "" || definition.path.toLowerCase().includes(needle) || definition.label.toLowerCase().includes(needle))
    .slice(0, 25)
    .map((definition) => ({ name: `${definition.label} (${definition.path})`.slice(0, 100), value: definition.path }));
}

export const whitelistAddHandler: CommandHandler = async (context) => {
  const target = context.interaction.options.getUser("target", true);
  const scope = context.interaction.options.getString("scope", true) as WhitelistScope;
  const reason = context.interaction.options.getString("reason", true);
  const hours = context.interaction.options.getInteger("hours");
  await planAndConfirm(context, [{ kind: "whitelistAdd", subjectId: target.id, scope, reason, hours }], "Confirm whitelist entry");
};

export const whitelistRemoveHandler: CommandHandler = async (context) => {
  const target = context.interaction.options.getUser("target", true);
  const reason = context.interaction.options.getString("reason", true);
  const fromFile = context.policy.policy.securityAdminIds.includes(target.id) || context.policy.policy.bots.approvedBotIds.includes(target.id);
  if (!context.policy.whitelist.some((entry) => entry.subjectId === target.id)) {
    await respond(context, {
      content: fromFile
        ? `${sanitize(target.username, 40)} has no whitelist entry; it is trusted through the security administrators or approved bots lists (\`/security panel\`).`
        : `${sanitize(target.username, 40)} has no active whitelist entry.`
    });
    return;
  }
  await planAndConfirm(context, [{ kind: "whitelistRevoke", subjectIds: [target.id], reason }], "Confirm whitelist removal");
};

export const protectRoleHandler: CommandHandler = async (context) => {
  const role = context.interaction.options.getRole("role", true);
  const action = context.interaction.options.getString("action", true);
  const granter = context.interaction.options.getUser("granter");
  const granterRole = context.interaction.options.getRole("granter-role");
  const rule = context.policy.protectedRoles.get(role.id);
  if (action === "unprotect") {
    if (rule?.source === "config") {
      await respond(context, { content: "This role is protected by the configuration file on the host and can only be unprotected there." });
      return;
    }
    const existing = (await context.deps.kernel.deps.repos.protectedRoles.list(context.guildId)).map((record) => record.roleId);
    await planAndConfirm(context, [{ kind: "protectedRoles", roleIds: existing.filter((id) => id !== role.id) }], "Confirm role unprotection");
    return;
  }
  await planAndConfirm(
    context,
    [
      {
        kind: "roleGranters",
        roleId: role.id,
        userIds: [...new Set([...(rule?.allowedGranterIds ?? []), ...(granter ? [granter.id] : [])])],
        roleIds: [...new Set([...(rule?.allowedGranterRoleIds ?? []), ...(granterRole ? [granterRole.id] : [])])]
      }
    ],
    "Confirm role protection"
  );
};
