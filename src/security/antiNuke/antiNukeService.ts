import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { CATEGORY_SCOPE, atLeastConfidence, atLeastSeverity, type ActionCategory, type ActionRecord, type Severity } from "../../core/types.js";
import type { IncidentRecord } from "../../database/repositories/incidentRepository.js";
import { auditConfidence, type AuditEvent } from "../../discord/auditEvent.js";
import type { DiscordGateway, GuildInfo } from "../../discord/gateway.js";
import { CATEGORY_PERMISSIONS } from "../../discord/permissions.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { CounterStore } from "../infra/counterStore.js";
import type { LockManager } from "../infra/lockManager.js";
import type { LockdownService } from "../lockdown/lockdownService.js";
import { trustActor } from "../policy/authorization.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip, type ContainmentResponder } from "../response/containment.js";

export interface RecoveryAdvisor {
  describe(guildId: string, category: ActionCategory): Promise<string | null>;
}

export const CATEGORY_SEVERITY: Record<ActionCategory, Severity> = {
  channelDelete: "critical",
  roleDelete: "critical",
  memberBan: "critical",
  memberPrune: "critical",
  channelCreate: "high",
  roleCreate: "high",
  roleUpdate: "high",
  memberKick: "high",
  memberRoleUpdate: "high",
  overwriteUpdate: "high",
  webhookCreate: "high",
  webhookDelete: "high",
  botAdd: "high",
  integrationCreate: "high",
  integrationDelete: "high",
  guildUpdate: "high",
  commandPermissionUpdate: "high",
  channelUpdate: "medium",
  webhookUpdate: "medium",
  integrationUpdate: "medium"
};

const DOWNGRADE: Record<Severity, Severity> = { critical: "high", high: "medium", medium: "low", low: "info", info: "info" };

interface OpenIncident {
  incident: IncidentRecord;
  targets: string[];
  expires: number;
}

export class AntiNukeService {
  private readonly open = new Map<string, OpenIncident>();

  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly responder: ContainmentResponder,
    private readonly lockdown: LockdownService,
    private readonly counters: CounterStore,
    private readonly locks: LockManager,
    private readonly recovery: RecoveryAdvisor,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  hasOpenIncident(guildId: string, category: ActionCategory): boolean {
    const now = this.clock.now();
    for (const [key, entry] of this.open) {
      if (entry.expires > now && key.startsWith(`${guildId}:${category}:`)) return true;
    }
    return false;
  }

  async onAuditEvent(event: AuditEvent): Promise<void> {
    const category = event.category;
    if (!category) return;
    const context = await this.policies.context(event.guildId);
    if (!context.policy.antiNuke.enabled) return;
    const guild = await this.gateway.getGuild(event.guildId);
    if (!guild) return;
    const actor = event.executorId;
    if (!actor) {
      await this.onUnattributedAction(event.guildId, category, event.targetId);
      return;
    }
    if (actor === guild.botUserId) return;
    const now = this.clock.now();
    const threshold = context.policy.antiNuke.thresholds[category];
    const factor = this.lockdown.isActive(event.guildId) ? context.policy.antiNuke.lockdownThresholdFactor : 1;
    const limit = Math.max(1, Math.floor(threshold.limit * factor));
    const windowMs = threshold.windowSeconds * 1000;
    const count = await this.counters.hit(`nuke:${event.guildId}:${category}:${actor}`, windowMs, now);
    const key = `${event.guildId}:${category}:${actor}`;
    this.sweep(now);
    const existing = this.open.get(key);
    if (existing) {
      if (event.targetId && existing.targets.length < 200) existing.targets.push(event.targetId);
      existing.expires = now + windowMs * 2;
      await this.evidence.append({
        guildId: event.guildId,
        eventType: `nuke.${category}.continued`,
        severity: "medium",
        actorId: actor,
        targetId: event.targetId,
        confidence: auditConfidence(event),
        incidentId: existing.incident.id,
        evidence: { auditEntryId: event.id, action: event.actionName, countInWindow: count }
      });
      return;
    }
    if (count < limit) return;
    if (!(await this.locks.once(`nuke-incident:${key}`, windowMs))) return;
    await this.handleThreshold(context, guild, event, category, actor, count, limit, now, windowMs);
  }

  async onUnattributedAction(guildId: string, category: ActionCategory, targetId: string | null): Promise<void> {
    const context = await this.policies.context(guildId);
    if (!context.policy.antiNuke.enabled) return;
    const now = this.clock.now();
    const threshold = context.policy.antiNuke.thresholds[category];
    const windowMs = threshold.windowSeconds * 1000;
    const count = await this.counters.hit(`nuke:any:${guildId}:${category}`, windowMs, now);
    const limit = Math.max(2, Math.ceil(threshold.limit * context.policy.antiNuke.unattributedSpikeFactor));
    if (count < limit || this.hasOpenIncident(guildId, category)) return;
    if (!(await this.locks.once(`nuke-spike:${guildId}:${category}`, windowMs))) return;
    await this.incidents.open({
      guildId,
      type: `nuke.${category}.unattributed-spike`,
      severity: DOWNGRADE[CATEGORY_SEVERITY[category]],
      actorId: null,
      targetId,
      confidence: "low",
      status: "needs-review",
      summary: `${count} ${category} events in ${threshold.windowSeconds}s without a matching audit log author. No automatic action is taken against anyone because the author is unknown. Check the audit log manually.`,
      details: { category, count, windowSeconds: threshold.windowSeconds }
    });
  }

  private async handleThreshold(
    context: PolicyContext,
    guild: GuildInfo,
    event: AuditEvent,
    category: ActionCategory,
    actor: string,
    count: number,
    limit: number,
    now: number,
    windowMs: number
  ): Promise<void> {
    const policy = context.policy.antiNuke;
    const confidence = auditConfidence(event);
    const trust = trustActor(context, guild, actor, CATEGORY_SCOPE[category]);
    const isOwner = actor === guild.ownerId;
    const isSecurityAdmin = context.policy.securityAdminIds.includes(actor);
    const whitelisted = trust.trusted && !isOwner && !isSecurityAdmin;
    const baseSeverity = CATEGORY_SEVERITY[category];
    const evidence = {
      auditEntryId: event.id,
      action: event.actionName,
      category,
      countInWindow: count,
      limit,
      windowSeconds: windowMs / 1000,
      reason: event.reason,
      trust: trust.reason,
      lockdownActive: this.lockdown.isActive(event.guildId)
    };
    if (whitelisted) {
      await this.evidence.append({ guildId: event.guildId, eventType: `nuke.${category}.whitelisted`, severity: "low", actorId: actor, targetId: event.targetId, confidence, evidence });
      if (count < limit * 3) return;
    }
    const recoveryNote = category === "channelDelete" || category === "roleDelete" ? await this.recovery.describe(event.guildId, category) : null;
    const severity: Severity = whitelisted || isSecurityAdmin ? DOWNGRADE[baseSeverity] : baseSeverity;
    const summaryParts = [`${count} ${category} actions by the same account in ${windowMs / 1000}s (limit ${limit}).`];
    if (isOwner) summaryParts.push("The actor is the server owner. Discord does not allow any bot to restrict the owner; if this is not expected, secure the owner account immediately (password, 2FA, active sessions).");
    if (isSecurityAdmin) summaryParts.push("The actor is a configured security administrator and is exempt from automatic containment.");
    if (whitelisted) summaryParts.push(`The actor is whitelisted (${trust.reason}) but exceeded three times the threshold.`);
    if (recoveryNote) summaryParts.push(recoveryNote);
    const incident = await this.incidents.open({
      guildId: event.guildId,
      type: `nuke.${category}`,
      severity,
      actorId: actor,
      targetId: event.targetId,
      confidence,
      summary: summaryParts.join(" "),
      details: { ...evidence, targets: event.targetId ? [event.targetId] : [] }
    });
    this.open.set(`${event.guildId}:${category}:${actor}`, { incident, targets: event.targetId ? [event.targetId] : [], expires: now + windowMs * 2 });
    const actions: ActionRecord[] = [];
    if (isOwner || isSecurityAdmin || whitelisted) {
      actions.push(skip("contain-actor", actor, isOwner ? "owner cannot be restricted" : "actor is exempt from automatic containment by policy"));
    } else if (context.policy.mode !== "automatic") {
      actions.push(skip("contain-actor", actor, "monitor mode: containment disabled"));
    } else if (policy.response !== "contain") {
      actions.push(skip("contain-actor", actor, "antiNuke.response is alert"));
    } else if (!atLeastConfidence(confidence, policy.minConfidenceToContain)) {
      actions.push(skip("contain-actor", actor, `attribution confidence ${confidence} is below ${policy.minConfidenceToContain}`));
    } else {
      const member = await this.gateway.getMember(event.guildId, actor);
      const reason = `Val Protection: ${count} ${category} actions in ${windowMs / 1000}s (incident ${incident.id})`;
      if (member?.isBot) {
        actions.push(
          policy.containBotsByKick
            ? await this.responder.kickBot(event.guildId, actor, reason)
            : skip("kick-bot", actor, "antiNuke.containBotsByKick is false")
        );
      } else {
        actions.push(...(await this.responder.stripPermissionRoles(event.guildId, actor, CATEGORY_PERMISSIONS[category], reason)));
      }
    }
    await this.incidents.recordActions(incident, actions);
    if (
      context.policy.mode === "automatic" &&
      policy.autoLockdownOnSeverity !== "never" &&
      atLeastSeverity(severity, policy.autoLockdownOnSeverity) &&
      !this.lockdown.isActive(event.guildId)
    ) {
      await this.lockdown.activate({ guildId: event.guildId, reason: incident.summary.slice(0, 300), triggeredBy: `auto:${incident.type}`, automatic: true, incidentId: incident.id });
    }
    this.logger.warn({ guildId: event.guildId, incidentId: incident.id, category, actor, count }, "Anti-nuke threshold reached");
  }

  private sweep(now: number): void {
    for (const [key, entry] of this.open) if (entry.expires <= now) this.open.delete(key);
  }
}
