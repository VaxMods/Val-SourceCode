import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { ActionRecord } from "../../core/types.js";
import type { IncidentRecord } from "../../database/repositories/incidentRepository.js";
import type { DiscordGateway, MemberInfo } from "../../discord/gateway.js";
import type { AlertSink } from "../alerts/alertService.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import { canKick, canManageRole, canTimeout } from "../hierarchy.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { CounterStore } from "../infra/counterStore.js";
import type { LockManager } from "../infra/lockManager.js";
import type { LockdownService } from "../lockdown/lockdownService.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip } from "../response/containment.js";
import { RaidDetector, type RaidAssessment, type RaidKind } from "./raidDetector.js";
import { assessJoin, type JoinSample, type RiskAssessment } from "./riskScorer.js";

interface RaidState {
  kind: RaidKind;
  incident: IncidentRecord;
  startedAt: number;
  lastSignalAt: number;
  joins: number;
  actioned: number;
  peakScore: number;
}

const ACTIONED_TTL_MS = 24 * 3600000;

export interface JoinOutcome {
  assessment: RiskAssessment;
  raid: RaidAssessment;
  actions: ActionRecord[];
}

export class AntiRaidService {
  private readonly detectors = new Map<string, RaidDetector>();
  private readonly raids = new Map<string, RaidState>();

  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly alerts: AlertSink,
    private readonly lockdown: LockdownService,
    private readonly counters: CounterStore,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  isRaidActive(guildId: string): boolean {
    return this.raids.has(guildId);
  }

  activeRaid(guildId: string): RaidState | null {
    return this.raids.get(guildId) ?? null;
  }

  async onMemberJoin(member: MemberInfo): Promise<JoinOutcome | null> {
    if (member.isBot) return null;
    const context = await this.policies.context(member.guildId);
    const settings = context.policy.antiRaid;
    if (!settings.enabled) return null;
    const now = this.clock.now();
    const detector = this.detectorFor(member.guildId);
    const raidActive = this.raids.has(member.guildId);
    const sample: JoinSample = {
      userId: member.id,
      username: member.username,
      joinedAt: member.joinedAt ?? now,
      accountCreatedAt: member.accountCreatedAt,
      hasAvatar: member.hasAvatar,
      flaggedSpammer: member.flaggedSpammer
    };
    const actionedKey = `raid:actioned:${member.guildId}:${member.id}`;
    const rejoin = (await this.counters.count(actionedKey, ACTIONED_TTL_MS, now)) > 0;
    const assessment = assessJoin(sample, detector.recent(now, settings), settings, rejoin, now);
    detector.record({ ...sample, joinedAt: now, score: assessment.score, clustered: assessment.clustered }, settings, raidActive || this.lockdown.isActive(member.guildId));
    if (assessment.score >= Math.ceil(settings.suspectScoreThreshold / 2)) {
      await this.evidence.append({
        guildId: member.guildId,
        eventType: "raid.join.assessed",
        severity: assessment.score >= settings.suspectScoreThreshold ? "low" : "info",
        targetId: member.id,
        confidence: "medium",
        evidence: { score: assessment.score, signals: assessment.signals, accountCreatedAt: new Date(member.accountCreatedAt).toISOString() },
        incidentId: this.raids.get(member.guildId)?.incident.id ?? null
      });
    }
    if (rejoin) await this.trackBypass(context, member.id, now);
    const raid = detector.evaluate(now, settings, raidActive);
    if (raid.detected) await this.onRaidSignal(context, raid, now);
    const actions = await this.applyMeasures(context, member, assessment);
    const state = this.raids.get(member.guildId);
    if (state) {
      state.joins += 1;
      if (actions.some((record) => record.outcome.ok)) state.actioned += 1;
    }
    for (const record of actions) {
      await this.evidence.append({
        guildId: member.guildId,
        eventType: "raid.measure",
        severity: record.outcome.ok ? "low" : "info",
        targetId: member.id,
        confidence: "medium",
        action: record.action,
        actionResult: record.outcome.skipped ? "skipped" : record.outcome.ok ? "success" : "failure",
        evidence: { rationale: record.rationale, score: assessment.score },
        error: record.outcome.error ?? null,
        incidentId: state?.incident.id ?? null
      });
      if (record.outcome.ok) await this.counters.hit(actionedKey, ACTIONED_TTL_MS, now);
    }
    return { assessment, raid, actions };
  }

  async tick(): Promise<void> {
    const now = this.clock.now();
    for (const [guildId, state] of [...this.raids]) {
      try {
        const context = await this.policies.context(guildId);
        const cooldown = context.policy.antiRaid.raidCooldownMinutes * 60000;
        if (now - state.lastSignalAt < cooldown) continue;
        this.raids.delete(guildId);
        await this.incidents.setStatus(state.incident, "monitoring", "raid signals ended");
        await this.evidence.append({
          guildId,
          eventType: "raid.ended",
          severity: "medium",
          incidentId: state.incident.id,
          evidence: { kind: state.kind, joins: state.joins, actioned: state.actioned, durationSeconds: Math.round((now - state.startedAt) / 1000) }
        });
        await this.alerts.send({
          guildId,
          severity: "medium",
          title: "Raid signals ended",
          description: `No raid signal for ${context.policy.antiRaid.raidCooldownMinutes} minutes. Joins observed during the raid: ${state.joins}. Members with a protective measure: ${state.actioned}.${this.lockdown.isActive(guildId) ? " Lockdown is still active; review before running /security unlock." : ""}`,
          incidentId: state.incident.id
        });
        this.logger.info({ guildId, incidentId: state.incident.id }, "Raid signals ended");
      } catch (error) {
        this.logger.error({ err: errorMessage(error), guildId }, "Raid tick failed");
      }
    }
  }

  private async onRaidSignal(context: PolicyContext, raid: RaidAssessment, now: number): Promise<void> {
    const guildId = context.guildId;
    await this.locks.withLock(`raid:${guildId}`, 15000, async () => {
      const existing = this.raids.get(guildId);
      if (existing) {
        existing.lastSignalAt = now;
        existing.peakScore = Math.max(existing.peakScore, raid.raidScore);
        return;
      }
      const kind = raid.detected as RaidKind;
      const severity = kind === "surge" && raid.raidScore >= 80 ? "critical" : "high";
      const summary =
        kind === "surge"
          ? `Join surge detected: ${raid.joinsInWindow} joins in ${context.policy.antiRaid.windowSeconds}s (threshold ${raid.threshold}, baseline ${raid.baseline}), ${raid.suspiciousInWindow} suspicious, raid score ${raid.raidScore}.`
          : `Wave of suspicious accounts detected: ${raid.suspiciousInSlowWindow} suspicious joins in ${context.policy.antiRaid.slowWaveWindowMinutes} minutes.`;
      const incident = await this.incidents.open({
        guildId,
        type: kind === "surge" ? "raid.surge" : "raid.suspicious-wave",
        severity,
        actorId: null,
        targetId: null,
        confidence: kind === "surge" ? "high" : "medium",
        summary,
        details: { assessment: raid, mode: context.policy.mode },
        fields: [
          { name: "Mode", value: context.policy.mode, inline: true },
          { name: "Measures", value: context.policy.mode === "automatic" ? `suspects: ${context.policy.antiRaid.suspectAction} (never ban)` : "monitor only", inline: true }
        ]
      });
      this.raids.set(guildId, { kind, incident, startedAt: now, lastSignalAt: now, joins: 0, actioned: 0, peakScore: raid.raidScore });
      if (context.policy.mode === "automatic" && context.policy.antiRaid.autoLockdown && !this.lockdown.isActive(guildId)) {
        await this.lockdown.activate({ guildId, reason: summary, triggeredBy: `auto:${incident.type}`, automatic: true, incidentId: incident.id });
      }
    });
  }

  private async applyMeasures(context: PolicyContext, member: MemberInfo, assessment: RiskAssessment): Promise<ActionRecord[]> {
    const settings = context.policy.antiRaid;
    const inRaid = this.raids.has(context.guildId);
    const inLockdown = this.lockdown.isActive(context.guildId);
    const lockdownQuarantine = inLockdown && context.policy.lockdown.quarantineNewMembers && settings.quarantineRoleId !== null;
    const suspicious = assessment.score >= settings.suspectScoreThreshold && (inRaid || inLockdown || !settings.actOnlyDuringRaid);
    if (!lockdownQuarantine && !suspicious) return [];
    if (context.policy.mode !== "automatic") {
      return [skip("raid-measure", member.id, `monitor mode: would apply ${lockdownQuarantine ? "quarantine (lockdown)" : settings.suspectAction} (score ${assessment.score})`)];
    }
    const guild = await this.gateway.getGuild(context.guildId);
    if (!guild) return [skip("raid-measure", member.id, "guild unavailable")];
    let measure: "quarantine" | "timeout" | "kick" | "none" = lockdownQuarantine ? "quarantine" : settings.suspectAction;
    if (measure === "kick" && !(inRaid && assessment.score >= settings.kickMinScore)) {
      measure = settings.quarantineRoleId ? "quarantine" : "timeout";
    }
    const reason = `Val Protection: ${lockdownQuarantine ? "lockdown access control" : `raid risk score ${assessment.score}`}`;
    switch (measure) {
      case "none":
        return [skip("raid-measure", member.id, "suspectAction is none; logged only")];
      case "quarantine": {
        const roleId = settings.quarantineRoleId;
        if (!roleId) return [skip("quarantine", member.id, "no quarantine role configured")];
        const role = await this.gateway.getRole(context.guildId, roleId);
        if (!role) return [skip("quarantine", member.id, "quarantine role no longer exists")];
        const capability = canManageRole(guild, role);
        if (!capability.ok) return [skip("quarantine", member.id, capability.reason ?? "cannot assign quarantine role")];
        const outcome = await this.gateway.addMemberRole(context.guildId, member.id, roleId, reason);
        return [{ action: "quarantine", target: member.id, rationale: reason, outcome }];
      }
      case "timeout": {
        const capability = canTimeout(guild, member);
        if (!capability.ok) return [skip("timeout", member.id, capability.reason ?? "cannot time out")];
        const outcome = await this.gateway.timeoutMember(context.guildId, member.id, settings.timeoutMinutes * 60000, reason);
        return [{ action: "timeout", target: member.id, rationale: reason, outcome }];
      }
      case "kick": {
        const capability = canKick(guild, member);
        if (!capability.ok) return [skip("kick", member.id, capability.reason ?? "cannot kick")];
        const outcome = await this.gateway.kickMember(context.guildId, member.id, `${reason} during an active raid`);
        return [{ action: "kick", target: member.id, rationale: `${reason} during an active raid (score >= ${settings.kickMinScore})`, outcome }];
      }
    }
  }

  private async trackBypass(context: PolicyContext, userId: string, now: number): Promise<void> {
    const count = await this.counters.hit(`raid:bypass:${context.guildId}`, 3600000, now);
    await this.evidence.append({ guildId: context.guildId, eventType: "raid.rejoin-after-measure", severity: "low", targetId: userId, confidence: "high", evidence: { rejoinsLastHour: count } });
    if (count >= 3 && (await this.locks.once(`raid:bypass-incident:${context.guildId}`, 3600000))) {
      await this.incidents.open({
        guildId: context.guildId,
        type: "raid.bypass-attempts",
        severity: "medium",
        actorId: null,
        targetId: userId,
        confidence: "medium",
        summary: `${count} accounts rejoined within an hour after being quarantined, timed out or kicked. This suggests attempts to bypass protective measures.`,
        details: { rejoinsLastHour: count }
      });
    }
  }

  private detectorFor(guildId: string): RaidDetector {
    let detector = this.detectors.get(guildId);
    if (!detector) {
      detector = new RaidDetector();
      this.detectors.set(guildId, detector);
    }
    return detector;
  }
}
