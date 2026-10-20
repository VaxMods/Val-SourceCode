import { describeActions, SEVERITY_COLOR, sanitize } from "../../security/alerts/format.js";
import { SCENARIOS, runScenarios, type ScenarioName } from "../../simulation/ruleTester.js";
import { defer, recordCommand, respond, timestamp, truncate, type CommandHandler } from "../context.js";

export const scanHandler: CommandHandler = async (context) => {
  await defer(context);
  const report = await context.deps.kernel.scanner.scan(context.guildId);
  if (!report) {
    await respond(context, { content: "The server is unavailable right now. Try again in a moment." });
    return;
  }
  await recordCommand(context, "command.scan", { counts: report.counts, findings: report.findings.length });
  const top = report.findings.slice(0, 12).map((finding) => `**[${finding.severity.toUpperCase()}]** ${sanitize(finding.title, 120)}\n${sanitize(finding.recommendation, 200)}`);
  await respond(context, {
    embeds: [
      {
        title: `Security scan • ${sanitize(report.guildName, 80)}`,
        color: report.counts.critical > 0 ? SEVERITY_COLOR.critical : report.counts.high > 0 ? SEVERITY_COLOR.high : SEVERITY_COLOR.low,
        description: truncate(top.join("\n\n") || "No finding. Keep reviewing regularly.", 4000),
        fields: [
          { name: "Findings", value: `critical ${report.counts.critical} • high ${report.counts.high} • medium ${report.counts.medium} • low ${report.counts.low} • info ${report.counts.info}`, inline: false },
          { name: "Members analysed", value: report.scannedMembers === null ? "skipped" : String(report.scannedMembers), inline: true },
          { name: "Notes", value: truncate(report.notes.join("\n") || "-", 1024), inline: false }
        ],
        footer: { text: "The full report is attached as JSON." }
      }
    ],
    files: [{ name: `scan-${context.guildId}.json`, data: Buffer.from(JSON.stringify(report, null, 2), "utf8") }]
  });
};

export const lockdownHandler: CommandHandler = async (context) => {
  const reason = context.interaction.options.getString("reason", true);
  const minutes = context.interaction.options.getInteger("minutes") ?? undefined;
  await defer(context);
  const result = await context.deps.kernel.lockdown.activate({
    guildId: context.guildId,
    reason: `${reason} (manual)`,
    triggeredBy: context.userId,
    automatic: false,
    ...(minutes !== undefined ? { durationMinutes: minutes } : {})
  });
  await recordCommand(context, "command.lockdown", { reason, minutes: minutes ?? null, changed: result.changed }, "high");
  await respond(context, {
    embeds: [
      {
        title: result.changed ? "Lockdown activated" : "Lockdown unchanged",
        color: SEVERITY_COLOR.high,
        description: `${result.message}\n${result.record ? `Automatic expiry ${timestamp(result.record.expiresAt)}.` : ""}\n\n${describeActions(result.actions)}`
      }
    ]
  });
};

export const unlockHandler: CommandHandler = async (context) => {
  const reason = context.interaction.options.getString("reason", true);
  const current = context.deps.kernel.lockdown.current(context.guildId);
  if (!current) {
    await respond(context, { content: "No lockdown is active." });
    return;
  }
  const { row } = context.deps.confirmations.create({
    guildId: context.guildId,
    userId: context.userId,
    action: "unlock",
    requiredAccess: "securityAdmin",
    execute: async () => {
      const result = await context.deps.kernel.lockdown.deactivate(context.guildId, context.userId, reason);
      await recordCommand(context, "command.unlock", { reason, changed: result.changed }, "high");
      return `${result.message}\n${describeActions(result.actions)}`;
    }
  });
  await respond(context, {
    embeds: [
      {
        title: "Confirm unlock",
        color: SEVERITY_COLOR.high,
        description: `Lockdown started ${timestamp(current.startedAt)} (${sanitize(current.reason, 300)}).\nEnding it restores the previous verification level and invites if they were changed by Val Protection.\nConfirm within 60 seconds.`
      }
    ],
    components: [row]
  });
};

export const testHandler: CommandHandler = async (context) => {
  const choice = context.interaction.options.getString("scenario") ?? "all";
  const names: ScenarioName[] = choice === "all" ? [...SCENARIOS] : SCENARIOS.filter((item) => item === choice);
  await defer(context);
  const results = await runScenarios(names, context.policy.policy, context.deps.kernel.policies.global);
  await recordCommand(context, "command.test", { scenarios: names, passed: results.filter((item) => item.passed).length });
  const lines = results.map((item) => `${item.passed ? "PASS" : "FAIL"} **${item.name}** — ${item.expectation}`);
  const full = results.map((item) => `${item.passed ? "PASS" : "FAIL"} ${item.name}\n  expectation: ${item.expectation}\n  ${item.observations.join("\n  ")}`).join("\n\n");
  await respond(context, {
    embeds: [
      {
        title: "Rule simulation",
        color: results.every((item) => item.passed) ? SEVERITY_COLOR.low : SEVERITY_COLOR.high,
        description: truncate(lines.join("\n"), 4000),
        footer: { text: `Simulated on a synthetic in-memory server with your thresholds and mode=automatic. Nothing was done to this server (current mode: ${context.policy.policy.mode}).` }
      }
    ],
    files: [{ name: "simulation.txt", data: Buffer.from(full, "utf8") }]
  });
};

export const recoverHandler: CommandHandler = async (context) => {
  const snapshotId = context.interaction.options.getString("snapshot")?.trim().toUpperCase() ?? undefined;
  if (snapshotId && !/^SNAP-[0-9A-F]{8}$/.test(snapshotId)) {
    await respond(context, { content: "Invalid snapshot ID. Expected a value such as SNAP-1A2B3C4D." });
    return;
  }
  await defer(context);
  const plan = await context.deps.kernel.snapshots.plan(context.guildId, snapshotId);
  if (!plan) {
    await respond(context, { content: "No snapshot is available for this server." });
    return;
  }
  if (!plan.integrity) {
    await respond(context, { content: `Snapshot ${plan.snapshotId} failed its integrity check and will not be used.` });
    return;
  }
  if (plan.missingRoles.length === 0 && plan.missingChannels.length === 0) {
    await respond(context, { content: `Nothing to recreate: every role and channel from ${plan.snapshotId} still exists. ${plan.permissionDrift.length} role(s) have different permissions; review them with /security roles.` });
    return;
  }
  const { row } = context.deps.confirmations.create({
    guildId: context.guildId,
    userId: context.userId,
    action: "recover",
    requiredAccess: "securityAdmin",
    execute: async () => {
      const actions = await context.deps.kernel.snapshots.execute(context.guildId, plan, context.userId);
      await recordCommand(context, "command.recover", { snapshotId: plan.snapshotId, actions: actions.length, failures: actions.filter((item) => !item.outcome.ok).length }, "medium");
      return truncate(describeActions(actions), 1800);
    }
  });
  await respond(context, {
    embeds: [
      {
        title: `Recovery preview • ${plan.snapshotId}`,
        color: SEVERITY_COLOR.medium,
        description: truncate(
          [
            `Snapshot taken ${timestamp(plan.snapshotAt)}.`,
            `Roles to recreate (${plan.missingRoles.length}): ${plan.missingRoles.map((role) => sanitize(role.name, 40)).join(", ") || "none"}`,
            `Channels to recreate (${plan.missingChannels.length}): ${plan.missingChannels.map((channel) => `#${sanitize(channel.name, 40)}`).join(", ") || "none"}`,
            "",
            ...plan.limitations.map((item) => `• ${item}`),
            "",
            "Make sure the attack is contained (lockdown, compromised accounts restricted) before confirming. Confirm within 60 seconds."
          ].join("\n"),
          4000
        )
      }
    ],
    components: [row]
  });
};
