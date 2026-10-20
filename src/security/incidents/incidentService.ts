import crypto from "node:crypto";
import type { APIEmbedField } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { HealthMonitor } from "../../core/health.js";
import type { ActionRecord, Confidence, Severity } from "../../core/types.js";
import type { IncidentRecord, IncidentRepository, IncidentStatus } from "../../database/repositories/incidentRepository.js";
import type { AlertSink } from "../alerts/alertService.js";
import { describeActions, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";

export interface IncidentDraft {
  guildId: string;
  type: string;
  severity: Severity;
  actorId: string | null;
  targetId: string | null;
  confidence: Confidence;
  summary: string;
  details: Record<string, unknown>;
  status?: IncidentStatus;
  fields?: APIEmbedField[];
  alert?: boolean;
}

export class IncidentService {
  constructor(
    private readonly repo: IncidentRepository,
    private readonly evidence: EvidenceSink,
    private readonly alerts: AlertSink,
    private readonly clock: Clock,
    private readonly logger: Logger,
    private readonly health: HealthMonitor
  ) {}

  static newId(): string {
    return `INC-${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
  }

  async open(draft: IncidentDraft): Promise<IncidentRecord> {
    const nowIso = new Date(this.clock.now()).toISOString();
    const record: IncidentRecord = {
      id: IncidentService.newId(),
      guildId: draft.guildId,
      type: draft.type,
      severity: draft.severity,
      status: draft.status ?? "open",
      actorId: draft.actorId,
      targetId: draft.targetId,
      confidence: draft.confidence,
      summary: draft.summary.slice(0, 1500),
      details: draft.details,
      createdAt: nowIso,
      updatedAt: nowIso
    };
    try {
      await this.repo.insert(record);
      this.health.healthy("incident-store");
    } catch (error) {
      if (this.health.degraded("incident-store", errorMessage(error))) {
        this.logger.error({ err: errorMessage(error) }, "Incident store unavailable; incident kept in logs only");
      }
      record.details = { ...record.details, persisted: false };
    }
    this.logger.warn({ guildId: record.guildId, incidentId: record.id, type: record.type, severity: record.severity, actorId: record.actorId }, record.summary);
    await this.evidence.append({
      guildId: record.guildId,
      eventType: `incident.opened.${record.type}`,
      severity: record.severity,
      actorId: record.actorId,
      targetId: record.targetId,
      confidence: record.confidence,
      evidence: { summary: record.summary, ...record.details },
      incidentId: record.id
    });
    if (draft.alert !== false) {
      await this.alerts.send({
        guildId: record.guildId,
        severity: record.severity,
        title: titleFor(record.type),
        description: record.summary,
        incidentId: record.id,
        fields: [
          { name: "Actor", value: userRef(record.actorId), inline: true },
          { name: "Confidence", value: record.confidence, inline: true },
          { name: "Status", value: record.status, inline: true },
          ...(draft.fields ?? [])
        ]
      });
    }
    return record;
  }

  async recordActions(incident: IncidentRecord, actions: readonly ActionRecord[], options: { alert?: boolean; statusOverride?: IncidentStatus } = {}): Promise<IncidentStatus> {
    for (const record of actions) {
      await this.evidence.append({
        guildId: incident.guildId,
        eventType: "response.action",
        severity: record.outcome.ok ? "info" : record.outcome.skipped ? "low" : "medium",
        actorId: incident.actorId,
        targetId: record.target,
        confidence: incident.confidence,
        action: record.action,
        actionResult: record.outcome.skipped ? "skipped" : record.outcome.ok ? "success" : "failure",
        evidence: { rationale: record.rationale, detail: record.outcome.detail ?? null },
        error: record.outcome.error ?? null,
        incidentId: incident.id
      });
    }
    const status = options.statusOverride ?? deriveStatus(actions);
    try {
      await this.repo.update(incident.id, { status, details: { ...incident.details, actions: actions.map(serializeAction) } }, new Date(this.clock.now()).toISOString());
    } catch (error) {
      this.logger.error({ err: errorMessage(error), incidentId: incident.id }, "Could not update incident status");
    }
    incident.status = status;
    if (options.alert !== false && actions.length > 0) {
      await this.alerts.send({
        guildId: incident.guildId,
        severity: status === "needs-review" ? incident.severity : "medium",
        title: `Response for ${incident.id}`,
        description: describeActions(actions),
        incidentId: incident.id,
        fields: [{ name: "Incident status", value: status, inline: true }]
      });
    }
    return status;
  }

  async setStatus(incident: IncidentRecord, status: IncidentStatus, note: string): Promise<void> {
    incident.status = status;
    try {
      await this.repo.update(incident.id, { status }, new Date(this.clock.now()).toISOString());
    } catch (error) {
      this.logger.error({ err: errorMessage(error), incidentId: incident.id }, "Could not update incident status");
    }
    await this.evidence.append({
      guildId: incident.guildId,
      eventType: "incident.status",
      severity: "info",
      incidentId: incident.id,
      evidence: { status, note }
    });
  }

  async get(guildId: string, id: string): Promise<IncidentRecord | null> {
    return this.repo.get(guildId, id);
  }

  async recent(guildId: string, limit: number, severities?: Severity[]): Promise<IncidentRecord[]> {
    return this.repo.recent(guildId, limit, severities);
  }
}

export function deriveStatus(actions: readonly ActionRecord[]): IncidentStatus {
  const executed = actions.filter((record) => !record.outcome.skipped);
  if (executed.length === 0) return "needs-review";
  if (executed.some((record) => !record.outcome.ok) || actions.some((record) => record.outcome.skipped)) return "needs-review";
  return "contained";
}

export function serializeAction(record: ActionRecord): Record<string, unknown> {
  return {
    action: record.action,
    target: record.target,
    rationale: record.rationale,
    ok: record.outcome.ok,
    skipped: record.outcome.skipped ?? false,
    detail: record.outcome.detail ?? null,
    error: record.outcome.error ?? null
  };
}

function titleFor(type: string): string {
  const words = type.split(/[.-]/).filter(Boolean);
  return words.map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(" ");
}
