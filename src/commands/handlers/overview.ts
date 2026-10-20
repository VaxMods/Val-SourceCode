import fs from "node:fs";
import path from "node:path";
import { SEVERITY_RANK, type Severity } from "../../core/types.js";
import { featureAvailability, dangerousBits, namesOf } from "../../discord/permissions.js";
import { SEVERITY_COLOR, sanitize, userRef } from "../../security/alerts/format.js";
import { respond, timestamp, truncate, type CommandHandler } from "../context.js";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function atLeast(min: Severity): Severity[] {
  return SEVERITIES.filter((severity) => SEVERITY_RANK[severity] >= SEVERITY_RANK[min]);
}

export const statusHandler: CommandHandler = async (context) => {
  const { kernel } = context.deps;
  const policy = context.policy.policy;
  const now = kernel.deps.clock.now();
  const lockdown = kernel.lockdown.current(context.guildId);
  const raid = kernel.antiRaid.activeRaid(context.guildId);
  const degradedFeatures = Object.entries(featureAvailability(context.guild.botPermissions))
    .filter(([, missing]) => missing.length > 0)
    .map(([feature, missing]) => `${feature}: missing ${missing.join(", ")}`);
  const health = kernel.deps.health.degradedComponents().map((item) => `${item.component}: ${item.reason ?? "degraded"}`);
  let incidents24h = "unavailable";
  let head = "unavailable";
  try {
    incidents24h = String(await kernel.deps.repos.incidents.countSince(context.guildId, new Date(now - 86400000).toISOString()));
    const current = await kernel.evidence.headOf(context.guildId);
    head = current ? `#${current.seq} (${current.hash.slice(0, 12)}…)` : "empty";
  } catch {
    health.push("database: unreachable");
  }
  const integrity = context.deps.integrity.get(context.guildId);
  const protections = [
    `Anti-raid: ${policy.antiRaid.enabled ? "on" : "OFF"}`,
    `Anti-nuke: ${policy.antiNuke.enabled ? `on (${policy.antiNuke.response})` : "OFF"}`,
    `Role protection: ${policy.roleProtection.enabled ? "on" : "OFF"}`,
    `Anti-spam: ${policy.antiSpam.enabled ? "on" : "OFF"}`,
    `Honeypot: ${policy.honeypot.enabled ? "on" : "OFF"}`
  ];
  await respond(context, {
    embeds: [
      {
        title: "Val Protection status",
        color: lockdown || raid ? SEVERITY_COLOR.high : degradedFeatures.length + health.length > 0 ? SEVERITY_COLOR.medium : SEVERITY_COLOR.low,
        fields: [
          { name: "Mode", value: policy.mode === "automatic" ? "automatic (responds)" : "monitor (alerts only)", inline: true },
          { name: "Lockdown", value: lockdown ? `ACTIVE, expires ${timestamp(lockdown.expiresAt)}` : "inactive", inline: true },
          { name: "Raid", value: raid ? `ACTIVE (${raid.kind}, ${raid.incident.id})` : "none", inline: true },
          { name: "Protections", value: protections.join("\n"), inline: false },
          { name: "Degraded features", value: truncate(degradedFeatures.join("\n") || "none", 1024), inline: false },
          { name: "Health", value: truncate(health.join("\n") || "all components healthy", 1024), inline: false },
          { name: "Incidents (24h)", value: incidents24h, inline: true },
          { name: "Evidence head", value: head, inline: true },
          { name: "Last integrity check", value: integrity ? `${integrity.ok ? "OK" : `BROKEN: ${integrity.reason}`} (${integrity.checked} records, ${timestamp(integrity.at)})` : "not run yet", inline: false },
          { name: "Alert channel", value: policy.alertChannelId ? `<#${policy.alertChannelId}>` : "not configured", inline: true },
          { name: "Storage", value: `${context.deps.databaseDriver}${context.deps.redisEnabled ? " + redis" : ""}`, inline: true },
          { name: "Config", value: `${kernel.policies.configHash.slice(0, 12)} (rev ${context.policy.revision})`, inline: true },
          { name: "Uptime", value: `since ${timestamp(context.deps.startedAt)}`, inline: true }
        ],
        footer: { text: "Val Protection cannot block actions before Discord executes them; it detects and responds within API limits." }
      }
    ]
  });
};

export const rolesHandler: CommandHandler = async (context) => {
  const roles = await context.deps.kernel.deps.gateway.listRoles(context.guildId);
  const lines: string[] = [];
  for (const role of [...roles].sort((a, b) => b.position - a.position)) {
    const rule = context.policy.protectedRoles.get(role.id);
    const dangerous = dangerousBits(role.permissions, context.policy.dangerousMask);
    if (!rule && dangerous === 0n) continue;
    const flags = [
      rule ? `protected (${rule.source})` : "dangerous",
      role.managed ? "bot role" : null,
      role.isEveryone ? "@everyone" : null,
      role.position >= context.guild.botHighestRolePosition ? "ABOVE Val Protection" : null
    ].filter(Boolean);
    const granters = rule && (rule.allowedGranterIds.length > 0 || rule.allowedGranterRoleIds.length > 0)
      ? ` • granters: ${[...rule.allowedGranterIds.map((id) => `<@${id}>`), ...rule.allowedGranterRoleIds.map((id) => `<@&${id}>`)].join(", ")}`
      : "";
    lines.push(`**${sanitize(role.name, 60)}** (${role.id}) [${flags.join(", ")}]\n${namesOf(dangerous).join(", ") || "no dangerous permission"}${granters}`);
  }
  await respond(context, {
    embeds: [
      {
        title: "Sensitive and protected roles",
        description: truncate(lines.join("\n\n") || "No sensitive role found.", 4000),
        color: SEVERITY_COLOR.medium,
        footer: { text: "Roles are judged by their effective permissions, never by their name." }
      }
    ]
  });
};

export const logsHandler: CommandHandler = async (context) => {
  const { kernel } = context.deps;
  const source = context.interaction.options.getString("source") ?? "incidents";
  const minimum = (context.interaction.options.getString("severity") ?? "info") as Severity;
  const limit = context.interaction.options.getInteger("limit") ?? 10;
  if (source === "verify") {
    const result = await kernel.evidence.verify(context.guildId);
    context.deps.integrity.set(context.guildId, { ok: result.ok, checked: result.checked, at: kernel.deps.clock.now(), reason: result.reason });
    await respond(context, {
      embeds: [
        {
          title: result.ok ? "Evidence chain intact" : "Evidence chain BROKEN",
          color: result.ok ? SEVERITY_COLOR.low : SEVERITY_COLOR.critical,
          description: result.ok
            ? `${result.checked} records verified (seq ${result.firstSeq ?? "-"} → ${result.lastSeq ?? "-"}). Every record matches its HMAC and the previous hash.`
            : `Verification failed at seq ${result.brokenAtSeq}: ${result.reason}. Records may have been modified or deleted outside Val Protection.`
        }
      ]
    });
    return;
  }
  if (source === "events") {
    const events = await kernel.deps.repos.events.recent(context.guildId, limit, atLeast(minimum));
    const lines = events.map(
      (event) =>
        `\`#${event.seq}\` ${timestamp(event.occurredAt)} **${event.severity}** ${event.eventType}${event.actorId ? ` by ${userRef(event.actorId)}` : ""}${event.action ? ` → ${event.action}: ${event.actionResult ?? "-"}` : ""}${event.incidentId ? ` (${event.incidentId})` : ""}`
    );
    await respond(context, { embeds: [{ title: "Evidence log", description: truncate(lines.join("\n") || "No records.", 4000), color: SEVERITY_COLOR.info }] });
    return;
  }
  const incidents = await kernel.incidents.recent(context.guildId, limit, atLeast(minimum));
  const lines = incidents.map(
    (incident) => `\`${incident.id}\` ${timestamp(incident.createdAt)} **${incident.severity}** ${incident.type} • ${incident.status}${incident.actorId ? ` • actor ${userRef(incident.actorId)}` : ""}`
  );
  await respond(context, { embeds: [{ title: "Recent incidents", description: truncate(lines.join("\n") || "No incidents.", 4000), color: SEVERITY_COLOR.info, footer: { text: "Use /security incident id:<ID> for details." } }] });
};

export const incidentHandler: CommandHandler = async (context) => {
  const raw = context.interaction.options.getString("id", true).trim().toUpperCase();
  if (!/^INC-[0-9A-F]{10}$/.test(raw)) {
    await respond(context, { content: "Invalid incident ID. Expected a value such as INC-1A2B3C4D5E." });
    return;
  }
  const incident = await context.deps.kernel.incidents.get(context.guildId, raw);
  if (!incident) {
    await respond(context, { content: `Incident ${raw} was not found on this server.` });
    return;
  }
  const events = await context.deps.kernel.deps.repos.events.forIncident(context.guildId, raw, 20);
  const timeline = events.map((event) => `\`#${event.seq}\` ${event.eventType}${event.action ? ` → ${event.action}: ${event.actionResult ?? "-"}` : ""}${event.error ? ` (${sanitize(event.error, 120)})` : ""}`);
  const details = JSON.stringify(incident.details, null, 2);
  await respond(context, {
    embeds: [
      {
        title: `${incident.id} • ${incident.type}`,
        description: sanitize(incident.summary, 2000),
        color: SEVERITY_COLOR[incident.severity],
        fields: [
          { name: "Severity", value: incident.severity, inline: true },
          { name: "Status", value: incident.status, inline: true },
          { name: "Confidence", value: incident.confidence, inline: true },
          { name: "Actor", value: userRef(incident.actorId), inline: true },
          { name: "Target", value: incident.targetId ?? "-", inline: true },
          { name: "Opened", value: timestamp(incident.createdAt), inline: true },
          { name: "Timeline", value: truncate(timeline.join("\n") || "no linked evidence", 1024), inline: false }
        ]
      }
    ],
    files: [{ name: `${incident.id}.json`, data: Buffer.from(details, "utf8") }]
  });
};

export const backupStatusHandler: CommandHandler = async (context) => {
  const { kernel } = context.deps;
  const snapshots = await kernel.snapshots.list(context.guildId, 5);
  const plan = snapshots.length > 0 ? await kernel.snapshots.plan(context.guildId) : null;
  let files: string[] = [];
  try {
    files = (await fs.promises.readdir(context.deps.backupDir))
      .filter((name) => name.startsWith("val-protection-"))
      .sort()
      .reverse()
      .slice(0, 5);
  } catch {
    files = [];
  }
  const fileLines = await Promise.all(
    files.map(async (name) => {
      const stat = await fs.promises.stat(path.join(context.deps.backupDir, name));
      return `${name} • ${(stat.size / 1024).toFixed(0)} KiB • ${timestamp(stat.mtimeMs)}`;
    })
  );
  const integrity = context.deps.integrity.get(context.guildId);
  await respond(context, {
    embeds: [
      {
        title: "Backups and integrity",
        color: SEVERITY_COLOR.info,
        fields: [
          {
            name: "Structural snapshots",
            value: truncate(snapshots.map((item) => `\`${item.id}\` ${timestamp(item.createdAt)} • ${item.roleCount} roles • ${item.channelCount} channels`).join("\n") || "none yet", 1024),
            inline: false
          },
          {
            name: "Difference with latest snapshot",
            value: plan
              ? `${plan.missingRoles.length} missing role(s), ${plan.missingChannels.length} missing channel(s), ${plan.permissionDrift.length} role(s) with changed permissions. Snapshot integrity: ${plan.integrity ? "OK" : "FAILED"}.`
              : "no snapshot",
            inline: false
          },
          { name: "Database backups", value: truncate(fileLines.join("\n") || `none in ${context.deps.backupDir} (run npm run backup or pg_dump)`, 1024), inline: false },
          { name: "Evidence integrity", value: integrity ? `${integrity.ok ? "OK" : "BROKEN"} • ${integrity.checked} records • ${timestamp(integrity.at)}` : "not verified yet (/security logs source:verify)", inline: false }
        ],
        footer: { text: "Snapshots store structure only. Messages and deleted objects cannot be restored." }
      }
    ]
  });
};
