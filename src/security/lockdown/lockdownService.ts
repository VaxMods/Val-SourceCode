import { GuildVerificationLevel } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { HealthMonitor } from "../../core/health.js";
import type { ActionRecord } from "../../core/types.js";
import type { LockdownPreviousState, LockdownRecord, LockdownRepository } from "../../database/repositories/lockdownRepository.js";
import type { DiscordGateway } from "../../discord/gateway.js";
import { has } from "../../discord/permissions.js";
import type { AlertSink } from "../alerts/alertService.js";
import { describeActions, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import type { LockManager } from "../infra/lockManager.js";
import type { PolicyService } from "../policy/policyService.js";
import { skip } from "../response/containment.js";

export const VERIFICATION_LEVELS: Record<"Medium" | "High" | "VeryHigh", number> = {
  Medium: GuildVerificationLevel.Medium,
  High: GuildVerificationLevel.High,
  VeryHigh: GuildVerificationLevel.VeryHigh
};

export interface LockdownRequest {
  guildId: string;
  reason: string;
  triggeredBy: string;
  automatic: boolean;
  durationMinutes?: number;
  incidentId?: string | null;
}

export interface LockdownResult {
  changed: boolean;
  record: LockdownRecord | null;
  actions: ActionRecord[];
  message: string;
}

export class LockdownService {
  private readonly active = new Map<string, LockdownRecord>();

  constructor(
    private readonly repo: LockdownRepository,
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly evidence: EvidenceSink,
    private readonly alerts: AlertSink,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger,
    private readonly health: HealthMonitor
  ) {}

  async initialize(): Promise<void> {
    try {
      for (const record of await this.repo.listActive()) this.active.set(record.guildId, record);
    } catch (error) {
      this.health.degraded("lockdown-store", errorMessage(error));
      this.logger.error({ err: errorMessage(error) }, "Could not load lockdown state");
    }
  }

  isActive(guildId: string): boolean {
    return this.active.has(guildId);
  }

  current(guildId: string): LockdownRecord | null {
    return this.active.get(guildId) ?? null;
  }

  async activate(request: LockdownRequest): Promise<LockdownResult> {
    return this.locks.withLock(`lockdown:${request.guildId}`, 30000, async () => {
      const existing = this.active.get(request.guildId);
      if (existing) return { changed: false, record: existing, actions: [], message: "Lockdown is already active." };
      const context = await this.policies.context(request.guildId);
      const settings = context.policy.lockdown;
      const guild = await this.gateway.getGuild(request.guildId);
      if (!guild) return { changed: false, record: null, actions: [], message: "Guild unavailable." };
      const now = this.clock.now();
      const minutes = Math.min(Math.max(5, request.durationMinutes ?? settings.maxDurationMinutes), settings.maxDurationMinutes);
      const expiresAt = now + minutes * 60000;
      const state: LockdownPreviousState = {
        verificationLevel: guild.verificationLevel,
        appliedVerificationLevel: null,
        invitesPausedByUs: false,
        pauseMethod: null
      };
      const actions: ActionRecord[] = [];
      const reason = `Val Protection lockdown: ${request.reason}`.slice(0, 400);
      if (settings.raiseVerificationLevel) {
        const target = VERIFICATION_LEVELS[settings.verificationLevel];
        if (guild.verificationLevel >= target) {
          actions.push(skip("raise-verification-level", request.guildId, "verification level already at or above the lockdown level"));
        } else if (!has(guild.botPermissions, "ManageGuild")) {
          actions.push(skip("raise-verification-level", request.guildId, "Val Protection lacks the Manage Server permission"));
        } else {
          const outcome = await this.gateway.setVerificationLevel(request.guildId, target, reason);
          if (outcome.ok) state.appliedVerificationLevel = target;
          actions.push({ action: "raise-verification-level", target: request.guildId, rationale: `verification level raised to ${settings.verificationLevel}`, outcome });
        }
      }
      if (settings.pauseInvites) {
        if (guild.invitesPaused) {
          actions.push(skip("pause-invites", request.guildId, "invites were already paused"));
        } else if (!has(guild.botPermissions, "ManageGuild")) {
          actions.push(skip("pause-invites", request.guildId, "Val Protection lacks the Manage Server permission"));
        } else {
          const outcome = await this.gateway.pauseInvites(request.guildId, expiresAt, reason);
          if (outcome.ok) {
            state.invitesPausedByUs = true;
            state.pauseMethod = outcome.method ?? null;
          }
          actions.push({ action: "pause-invites", target: request.guildId, rationale: "new joins paused until lockdown ends", outcome });
        }
      }
      const record: LockdownRecord = {
        guildId: request.guildId,
        active: true,
        reason: request.reason.slice(0, 500),
        triggeredBy: request.triggeredBy,
        startedAt: new Date(now).toISOString(),
        expiresAt: new Date(expiresAt).toISOString(),
        endedAt: null,
        endedBy: null,
        previousState: state
      };
      this.active.set(request.guildId, record);
      try {
        await this.repo.start(record);
      } catch (error) {
        this.health.degraded("lockdown-store", errorMessage(error));
        this.logger.error({ err: errorMessage(error) }, "Lockdown state could not be persisted; it is kept in memory");
      }
      await this.evidence.append({
        guildId: request.guildId,
        eventType: "lockdown.activated",
        severity: "high",
        actorId: request.automatic ? null : request.triggeredBy,
        action: "lockdown",
        actionResult: "active",
        incidentId: request.incidentId ?? null,
        evidence: { reason: record.reason, triggeredBy: request.triggeredBy, automatic: request.automatic, expiresAt: record.expiresAt, previousState: state }
      });
      await this.alerts.send({
        guildId: request.guildId,
        severity: "high",
        title: "Lockdown activated",
        description: [
          `Reason: ${record.reason}`,
          `Triggered by: ${request.automatic ? `automatic detection (${request.triggeredBy})` : userRef(request.triggeredBy)}`,
          `Automatic expiry: <t:${Math.floor(expiresAt / 1000)}:R>. Use /security unlock to end it earlier.`,
          "Administrators keep all their capabilities. Val Protection cannot restrict the server owner.",
          "",
          describeActions(actions)
        ].join("\n"),
        incidentId: request.incidentId ?? null
      });
      return { changed: true, record, actions, message: "Lockdown activated." };
    });
  }

  async deactivate(guildId: string, endedBy: string, reason: string): Promise<LockdownResult> {
    return this.locks.withLock(`lockdown:${guildId}`, 30000, async () => {
      const record = this.active.get(guildId);
      if (!record) return { changed: false, record: null, actions: [], message: "No active lockdown." };
      const guild = await this.gateway.getGuild(guildId);
      const actions: ActionRecord[] = [];
      const state = record.previousState;
      const restoreReason = `Val Protection lockdown ended: ${reason}`.slice(0, 400);
      if (guild && state.appliedVerificationLevel !== null && state.verificationLevel !== null) {
        if (guild.verificationLevel !== state.appliedVerificationLevel) {
          actions.push(skip("restore-verification-level", guildId, "verification level was changed manually during lockdown; leaving it untouched"));
        } else {
          const outcome = await this.gateway.setVerificationLevel(guildId, state.verificationLevel, restoreReason);
          actions.push({ action: "restore-verification-level", target: guildId, rationale: "restore the level that existed before lockdown", outcome });
        }
      }
      if (guild && state.invitesPausedByUs) {
        if (!guild.invitesPaused) {
          actions.push(skip("resume-invites", guildId, "invites were already resumed"));
        } else {
          const outcome = await this.gateway.pauseInvites(guildId, null, restoreReason);
          actions.push({ action: "resume-invites", target: guildId, rationale: "resume invites paused by the lockdown", outcome });
        }
      }
      if (!guild) actions.push(skip("restore-settings", guildId, "guild unavailable; restore verification level and invites manually"));
      this.active.delete(guildId);
      try {
        await this.repo.end(guildId, endedBy, new Date(this.clock.now()).toISOString());
      } catch (error) {
        this.health.degraded("lockdown-store", errorMessage(error));
        this.logger.error({ err: errorMessage(error) }, "Lockdown end could not be persisted");
      }
      await this.evidence.append({
        guildId,
        eventType: "lockdown.ended",
        severity: "medium",
        actorId: endedBy.startsWith("auto:") ? null : endedBy,
        action: "unlock",
        actionResult: actions.every((item) => item.outcome.ok || item.outcome.skipped) ? "success" : "partial",
        evidence: { reason, endedBy, startedAt: record.startedAt, actions: actions.map((item) => ({ action: item.action, ok: item.outcome.ok, detail: item.outcome.detail ?? item.outcome.error ?? null })) }
      });
      await this.alerts.send({
        guildId,
        severity: "medium",
        title: "Lockdown ended",
        description: [`Ended by: ${endedBy.startsWith("auto:") ? endedBy : userRef(endedBy)}`, `Reason: ${reason}`, "", describeActions(actions)].join("\n")
      });
      return { changed: true, record, actions, message: "Lockdown ended." };
    });
  }

  async expireDue(): Promise<void> {
    const now = this.clock.now();
    for (const record of [...this.active.values()]) {
      if (Date.parse(record.expiresAt) <= now) {
        try {
          await this.deactivate(record.guildId, "auto:expiry", "maximum lockdown duration reached");
        } catch (error) {
          this.logger.error({ err: errorMessage(error), guildId: record.guildId }, "Automatic lockdown expiry failed");
        }
      }
    }
  }
}
