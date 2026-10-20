import type { Logger } from "pino";
import { errorMessage } from "../core/errors.js";
import { ADMINISTRATOR, featureAvailability } from "../discord/permissions.js";
import type { SecurityKernel } from "../security/kernel.js";

export const VERSION = "1.1.0";

export async function verifyGuild(kernel: SecurityKernel, guildId: string, configWarnings: readonly string[], logger: Logger): Promise<void> {
  const guild = await kernel.deps.gateway.getGuild(guildId);
  if (!guild) {
    logger.warn({ guildId }, "Guild unavailable during startup verification");
    return;
  }
  const context = await kernel.policies.context(guildId);
  const policy = context.policy;
  const issues: string[] = [];
  const missing = Object.entries(featureAvailability(guild.botPermissions))
    .filter(([, list]) => list.length > 0)
    .map(([feature, list]) => `${feature} disabled (missing ${list.join(", ")})`);
  issues.push(...missing);
  if ((guild.botPermissions & ADMINISTRATOR) === ADMINISTRATOR) issues.push("Val Protection has Administrator; grant only the documented permissions instead");
  const channels = await kernel.deps.gateway.listChannels(guildId);
  if (!policy.alertChannelId) issues.push("no alert channel configured: run /security panel → General");
  else if (!channels.some((channel) => channel.id === policy.alertChannelId)) issues.push(`alert channel ${policy.alertChannelId} not found`);
  const roles = await kernel.deps.gateway.listRoles(guildId);
  const roleIds = new Set(roles.map((role) => role.id));
  for (const roleId of context.protectedRoles.keys()) if (!roleIds.has(roleId)) issues.push(`protected role ${roleId} not found`);
  const quarantine = policy.antiRaid.quarantineRoleId ? roles.find((role) => role.id === policy.antiRaid.quarantineRoleId) : null;
  if (policy.antiRaid.quarantineRoleId && !quarantine) issues.push("quarantine role not found: choose another one in /security panel → Anti-raid");
  if (quarantine && quarantine.permissions !== 0n) issues.push("quarantine role grants permissions; it should grant none");
  if (quarantine && quarantine.position >= guild.botHighestRolePosition) issues.push("quarantine role is above Val Protection and cannot be assigned");
  for (const decoyId of policy.honeypot.decoyRoleIds) {
    const decoy = roles.find((role) => role.id === decoyId);
    if (!decoy) issues.push(`decoy role ${decoyId} not found`);
    else if ((decoy.permissions & context.dangerousMask) !== 0n) issues.push(`decoy role ${decoy.name} carries dangerous permissions and is treated as a normal sensitive role`);
  }
  let configChanged = false;
  try {
    const previous = await kernel.deps.repos.events.latestOfType(guildId, "system.started");
    const previousHash = typeof previous?.evidence.configHash === "string" ? previous.evidence.configHash : null;
    configChanged = previousHash !== null && previousHash !== kernel.policies.configHash;
  } catch (error) {
    issues.push(`database unavailable: ${errorMessage(error)}`);
  }
  await kernel.evidence.append({
    guildId,
    eventType: "system.started",
    severity: issues.length > 0 || configChanged ? "medium" : "info",
    evidence: { version: VERSION, configHash: kernel.policies.configHash, configChanged, mode: policy.mode, issues, configWarnings: [...configWarnings] }
  });
  await kernel.alerts.send({
    guildId,
    severity: configChanged || issues.length > 0 ? "medium" : "info",
    title: "Val Protection online",
    description: [
      `Version ${VERSION} • mode **${policy.mode}** • lockdown ${kernel.lockdown.isActive(guildId) ? "ACTIVE" : "inactive"}`,
      configChanged ? `The configuration file changed since the previous start (now ${kernel.policies.configHash.slice(0, 12)}). Verify that the change was authorized.` : `Configuration ${kernel.policies.configHash.slice(0, 12)}.`,
      issues.length > 0 ? `\nIssues:\n${issues.map((item) => `• ${item}`).join("\n")}` : "\nAll startup checks passed."
    ].join("\n")
  });
  logger.info({ guildId, name: guild.name, issues: issues.length, configChanged }, "Guild verified");
}
