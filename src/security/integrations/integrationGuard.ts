import { AuditLogEvent } from "discord.js";
import type { Logger } from "pino";
import type { ActionRecord, Severity } from "../../core/types.js";
import { auditConfidence, findChange, type AuditEvent } from "../../discord/auditEvent.js";
import type { DiscordGateway, GuildInfo } from "../../discord/gateway.js";
import { has } from "../../discord/permissions.js";
import { channelRef, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import type { IncidentService } from "../incidents/incidentService.js";
import { trustActor } from "../policy/authorization.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip } from "../response/containment.js";

const SAFE_WEBHOOK_KEYS = new Set(["name", "channel_id", "type", "application_id"]);

export class IntegrationGuard {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly logger: Logger
  ) {}

  async onAuditEvent(event: AuditEvent): Promise<void> {
    switch (event.actionType) {
      case AuditLogEvent.WebhookCreate:
      case AuditLogEvent.WebhookUpdate:
      case AuditLogEvent.WebhookDelete:
        await this.onWebhook(event);
        return;
      case AuditLogEvent.IntegrationCreate:
      case AuditLogEvent.IntegrationUpdate:
      case AuditLogEvent.IntegrationDelete:
        await this.onIntegration(event);
        return;
      case AuditLogEvent.ApplicationCommandPermissionUpdate:
        await this.onCommandPermissions(event);
        return;
      default:
        return;
    }
  }

  private authorized(context: PolicyContext, guild: GuildInfo, actorId: string | null, scope: "webhooks" | "bots"): { ok: boolean; reason: string } {
    if (actorId && context.policy.integrations.authorizedManagerIds.includes(actorId)) return { ok: true, reason: "listed in integrations.authorizedManagerIds" };
    const trust = trustActor(context, guild, actorId, scope);
    return { ok: trust.trusted, reason: trust.reason };
  }

  private webhookDetails(event: AuditEvent): Record<string, unknown> {
    const details: Record<string, unknown> = { webhookId: event.targetId, auditEntryId: event.id, action: event.actionName };
    for (const change of event.changes) {
      if (SAFE_WEBHOOK_KEYS.has(change.key)) details[change.key] = { old: change.old, new: change.new };
    }
    return details;
  }

  private async onWebhook(event: AuditEvent): Promise<void> {
    const context = await this.policies.context(event.guildId);
    const guild = await this.gateway.getGuild(event.guildId);
    if (!guild || event.executorId === guild.botUserId) return;
    const auth = this.authorized(context, guild, event.executorId, "webhooks");
    const details = this.webhookDetails(event);
    const confidence = auditConfidence(event);
    if (auth.ok) {
      await this.evidence.append({ guildId: event.guildId, eventType: `webhook.${event.actionName}`, severity: "info", actorId: event.executorId, targetId: event.targetId, confidence, evidence: { ...details, authorization: auth.reason } });
      return;
    }
    const channelChange = findChange(event, "channel_id");
    const channelId = typeof channelChange?.new === "string" ? channelChange.new : typeof channelChange?.old === "string" ? channelChange.old : null;
    let severity: Severity = "medium";
    let summary: string;
    if (event.actionType === AuditLogEvent.WebhookCreate) {
      summary = `${userRef(event.executorId)} created a webhook in ${channelRef(channelId)} without authorization (${auth.reason}). Webhooks can post as any name and avatar.`;
    } else if (event.actionType === AuditLogEvent.WebhookUpdate) {
      severity = channelChange ? "medium" : "low";
      summary = `${userRef(event.executorId)} modified webhook ${event.targetId ?? "unknown"}${channelChange ? ` and moved it to ${channelRef(channelId)}` : ""} without authorization.`;
    } else {
      summary = `${userRef(event.executorId)} deleted webhook ${event.targetId ?? "unknown"} without authorization. Deleted webhooks cannot be restored; integrations using it must be reconfigured.`;
    }
    const incident = await this.incidents.open({
      guildId: event.guildId,
      type: `webhook.unauthorized-${event.actionType === AuditLogEvent.WebhookCreate ? "create" : event.actionType === AuditLogEvent.WebhookUpdate ? "update" : "delete"}`,
      severity,
      actorId: event.executorId,
      targetId: event.targetId,
      confidence,
      summary,
      details
    });
    if (event.actionType !== AuditLogEvent.WebhookCreate || !event.targetId) {
      await this.incidents.recordActions(incident, [], { alert: false, statusOverride: "needs-review" });
      return;
    }
    const actions: ActionRecord[] = [];
    if (context.policy.integrations.unauthorizedWebhookAction !== "delete") actions.push(skip("delete-webhook", event.targetId, "recommendation only: integrations.unauthorizedWebhookAction is alert"));
    else if (context.policy.mode !== "automatic") actions.push(skip("delete-webhook", event.targetId, "monitor mode: deletion recommended, not executed"));
    else if (confidence !== "high") actions.push(skip("delete-webhook", event.targetId, "creator not identified with high confidence"));
    else if (!has(guild.botPermissions, "ManageWebhooks")) actions.push(skip("delete-webhook", event.targetId, "Val Protection lacks the Manage Webhooks permission"));
    else {
      const outcome = await this.gateway.deleteWebhook(event.guildId, event.targetId, `Val Protection: unauthorized webhook (incident ${incident.id})`);
      actions.push({ action: "delete-webhook", target: event.targetId, rationale: "webhook created by an unauthorized account", outcome });
    }
    await this.incidents.recordActions(incident, actions);
  }

  private async onIntegration(event: AuditEvent): Promise<void> {
    const context = await this.policies.context(event.guildId);
    const guild = await this.gateway.getGuild(event.guildId);
    if (!guild || event.executorId === guild.botUserId) return;
    const auth = this.authorized(context, guild, event.executorId, "bots");
    const details: Record<string, unknown> = { integrationId: event.targetId, auditEntryId: event.id, action: event.actionName };
    for (const change of event.changes) if (change.key === "name" || change.key === "type") details[change.key] = change.new ?? change.old;
    if (auth.ok) {
      await this.evidence.append({ guildId: event.guildId, eventType: `integration.${event.actionName}`, severity: "info", actorId: event.executorId, targetId: event.targetId, confidence: auditConfidence(event), evidence: { ...details, authorization: auth.reason } });
      return;
    }
    await this.incidents.open({
      guildId: event.guildId,
      type: "integration.unauthorized-change",
      severity: event.actionType === AuditLogEvent.IntegrationUpdate ? "low" : "medium",
      actorId: event.executorId,
      targetId: event.targetId,
      confidence: auditConfidence(event),
      status: "needs-review",
      summary: `${userRef(event.executorId)} performed ${event.actionName} on an integration without authorization (${auth.reason}). Review Server Settings → Integrations.`,
      details
    });
  }

  private async onCommandPermissions(event: AuditEvent): Promise<void> {
    const context = await this.policies.context(event.guildId);
    const guild = await this.gateway.getGuild(event.guildId);
    if (!guild || event.executorId === guild.botUserId) return;
    const applicationId = typeof event.extra.applicationId === "string" ? event.extra.applicationId : event.targetId;
    const ours = applicationId === guild.botUserId;
    const auth = this.authorized(context, guild, event.executorId, "bots");
    if (auth.ok && !ours) {
      await this.evidence.append({ guildId: event.guildId, eventType: "commands.permissions-updated", severity: "info", actorId: event.executorId, targetId: applicationId, confidence: auditConfidence(event), evidence: { auditEntryId: event.id } });
      return;
    }
    await this.incidents.open({
      guildId: event.guildId,
      type: ours ? "tamper.command-permissions" : "commands.unauthorized-permission-change",
      severity: ours && !auth.ok ? "high" : ours ? "medium" : "low",
      actorId: event.executorId,
      targetId: applicationId,
      confidence: auditConfidence(event),
      status: "needs-review",
      summary: ours
        ? `${userRef(event.executorId)} changed who can use Val Protection commands. Access control inside Val Protection still applies, but verify this change in Server Settings → Integrations. Authorization: ${auth.reason}.`
        : `${userRef(event.executorId)} changed command permissions of application ${applicationId ?? "unknown"} without authorization.`,
      details: { auditEntryId: event.id, applicationId, changedKeys: event.changes.map((change) => change.key) }
    });
    this.logger.warn({ guildId: event.guildId, applicationId }, "Application command permissions changed");
  }
}
