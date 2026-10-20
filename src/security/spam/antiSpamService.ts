import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { ActionRecord } from "../../core/types.js";
import type { DiscordGateway } from "../../discord/gateway.js";
import { has } from "../../discord/permissions.js";
import type { AlertSink } from "../alerts/alertService.js";
import { channelRef, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import { canTimeout } from "../hierarchy.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { CounterStore } from "../infra/counterStore.js";
import type { LockManager } from "../infra/lockManager.js";
import type { LockdownService } from "../lockdown/lockdownService.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip } from "../response/containment.js";
import { analyzeContent, contentHash, type MessageSample, type SpamViolation } from "./contentRules.js";

export interface SpamAuthor {
  roleIds: string[];
  permissions: bigint;
  isOwner: boolean;
}

export type SanctionLevel = "none" | "warn" | "delete" | "timeout";

export interface SpamResult {
  violations: SpamViolation[];
  strikes: number;
  level: SanctionLevel;
  actions: ActionRecord[];
}

interface RecentMessage {
  id: string;
  channelId: string;
  at: number;
}

interface SlowmodeRestore {
  guildId: string;
  channelId: string;
  previous: number;
  applied: number;
  until: number;
}

const WARN_AT = 1;
const DELETE_AT = 3;
const TIMEOUT_AT = 5;

export class AntiSpamService {
  private readonly recent = new Map<string, RecentMessage[]>();
  private readonly slowmodes = new Map<string, SlowmodeRestore>();

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

  isExempt(context: PolicyContext, message: Pick<MessageSample, "channelId">, author: SpamAuthor): boolean {
    const settings = context.policy.antiSpam;
    if (author.isOwner) return true;
    if (settings.exemptChannelIds.includes(message.channelId)) return true;
    if (author.roleIds.some((roleId) => settings.exemptRoleIds.includes(roleId) || context.policy.staffRoleIds.includes(roleId))) return true;
    return has(author.permissions, "ManageMessages");
  }

  async onMessage(message: MessageSample, author: SpamAuthor): Promise<SpamResult | null> {
    const context = await this.policies.context(message.guildId);
    const settings = context.policy.antiSpam;
    if (!settings.enabled || this.isExempt(context, message, author)) return null;
    const now = this.clock.now();
    this.remember(message, now);
    const violations = analyzeContent(message, settings);
    const burstCount = await this.counters.hit(`spam:burst:${message.guildId}:${message.authorId}`, settings.burst.windowSeconds * 1000, now);
    if (burstCount > settings.burst.maxMessages && (await this.locks.once(`spam:burst-flag:${message.guildId}:${message.authorId}`, settings.burst.windowSeconds * 1000))) {
      violations.push({ kind: "burst", severity: "medium", strikes: 1, detail: `${burstCount} messages in ${settings.burst.windowSeconds}s`, deleteMessage: true });
      await this.trackFlood(context, message, now);
    }
    const hash = contentHash(message.content);
    if (hash) {
      const duplicates = await this.counters.hit(`spam:dup:${message.guildId}:${message.authorId}:${hash}`, settings.duplicates.windowSeconds * 1000, now);
      if (duplicates >= settings.duplicates.max) {
        violations.push({ kind: "duplicate", severity: "medium", strikes: 1, detail: `same message sent ${duplicates} times in ${settings.duplicates.windowSeconds}s`, deleteMessage: true });
      }
    }
    if (violations.length === 0) return { violations, strikes: 0, level: "none", actions: [] };
    return this.sanction(context, message, author, violations, now);
  }

  async onThreadCreated(guildId: string, threadId: string, ownerId: string, author: SpamAuthor, parentId: string | null): Promise<SpamResult | null> {
    const context = await this.policies.context(guildId);
    const settings = context.policy.antiSpam;
    if (!settings.enabled || this.isExempt(context, { channelId: parentId ?? threadId }, author)) return null;
    const now = this.clock.now();
    const count = await this.counters.hit(`spam:threads:${guildId}:${ownerId}`, settings.threads.windowSeconds * 1000, now);
    if (count <= settings.threads.max) return null;
    const violation: SpamViolation = { kind: "thread-flood", severity: "medium", strikes: 2, detail: `${count} threads in ${settings.threads.windowSeconds}s`, deleteMessage: false };
    return this.sanction(context, { id: threadId, guildId, channelId: parentId ?? threadId, authorId: ownerId, content: "", mentionCount: 0, canMentionEveryone: false, createdAt: now }, author, [violation], now);
  }

  async tick(): Promise<void> {
    const now = this.clock.now();
    for (const [key, entry] of [...this.slowmodes]) {
      if (entry.until > now) continue;
      this.slowmodes.delete(key);
      try {
        const current = await this.gateway.getChannelSlowmode(entry.guildId, entry.channelId);
        if (current !== entry.applied) continue;
        const outcome = await this.gateway.setChannelSlowmode(entry.guildId, entry.channelId, entry.previous, "Val Protection: flood slowmode expired");
        await this.evidence.append({ guildId: entry.guildId, eventType: "spam.slowmode.restored", severity: "info", targetId: entry.channelId, action: "restore-slowmode", actionResult: outcome.ok ? "success" : "failure", error: outcome.error ?? null });
      } catch (error) {
        this.logger.error({ err: errorMessage(error) }, "Slowmode restore failed");
      }
    }
    for (const [key, messages] of this.recent) {
      if (messages.every((item) => item.at < now - 600000)) this.recent.delete(key);
    }
  }

  private async sanction(context: PolicyContext, message: MessageSample, author: SpamAuthor, violations: SpamViolation[], now: number): Promise<SpamResult> {
    const settings = context.policy.antiSpam;
    const weight = violations.reduce((sum, violation) => sum + violation.strikes, 0);
    const strikes = await this.counters.hit(`spam:strikes:${message.guildId}:${message.authorId}`, settings.strikeDecaySeconds * 1000, now, weight);
    let level: SanctionLevel = strikes >= TIMEOUT_AT ? "timeout" : strikes >= DELETE_AT ? "delete" : strikes >= WARN_AT ? "warn" : "none";
    const forceDelete = violations.some((violation) => violation.deleteMessage && violation.severity === "high");
    if (forceDelete && level === "warn") level = "delete";
    const actions: ActionRecord[] = [];
    const automatic = context.policy.mode === "automatic";
    const reason = `Val Protection anti-spam: ${violations.map((violation) => violation.detail).join("; ")}`.slice(0, 400);
    if (!automatic) {
      actions.push(skip(`spam-${level}`, message.authorId, "monitor mode: sanction recommended, not executed"));
    } else {
      if (level === "delete" || level === "timeout" || forceDelete) actions.push(await this.deleteRecent(message, violations, reason));
      if (level === "warn" || level === "delete") {
        const warning = await this.warn(context, message);
        if (warning) actions.push(warning);
      }
      if (level === "timeout") actions.push(await this.timeout(message, settings.timeoutMinutes, reason));
    }
    await this.evidence.append({
      guildId: message.guildId,
      eventType: "spam.violation",
      severity: level === "timeout" ? "medium" : "low",
      actorId: message.authorId,
      targetId: message.channelId,
      confidence: "high",
      action: level,
      actionResult: actions.map((record) => `${record.action}:${record.outcome.skipped ? "skipped" : record.outcome.ok ? "ok" : "failed"}`).join(",") || null,
      evidence: { violations: violations.map(({ kind, severity, detail }) => ({ kind, severity, detail })), strikes, messageId: message.id }
    });
    if (level === "timeout" && (await this.locks.once(`spam:incident:${message.guildId}:${message.authorId}`, settings.strikeDecaySeconds * 1000))) {
      const incident = await this.incidents.open({
        guildId: message.guildId,
        type: "spam.repeat-offender",
        severity: "medium",
        actorId: message.authorId,
        targetId: message.channelId,
        confidence: "high",
        summary: `${userRef(message.authorId)} reached ${strikes} spam strikes in ${channelRef(message.channelId)}: ${violations.map((violation) => violation.detail).join("; ")}.`,
        details: { strikes, violations: violations.map(({ kind, detail }) => ({ kind, detail })) }
      });
      await this.incidents.recordActions(incident, actions, { alert: false, statusOverride: automatic ? "contained" : "needs-review" });
    }
    return { violations, strikes, level, actions };
  }

  private async deleteRecent(message: MessageSample, violations: SpamViolation[], reason: string): Promise<ActionRecord> {
    const bulk = violations.some((violation) => violation.kind === "burst" || violation.kind === "duplicate");
    const key = `${message.guildId}:${message.authorId}`;
    const now = this.clock.now();
    const targets = bulk ? (this.recent.get(key) ?? []).filter((item) => item.at >= now - 120000) : [{ id: message.id, channelId: message.channelId, at: now }];
    if (message.content === "" && !bulk) return skip("delete-messages", message.authorId, "nothing to delete");
    const byChannel = new Map<string, string[]>();
    for (const item of targets) byChannel.set(item.channelId, [...(byChannel.get(item.channelId) ?? []), item.id]);
    if (!byChannel.has(message.channelId) && message.content !== "") byChannel.set(message.channelId, [message.id]);
    let deleted = 0;
    const errors: string[] = [];
    for (const [channelId, ids] of byChannel) {
      const outcome = await this.gateway.deleteMessages(message.guildId, channelId, ids, reason);
      if (outcome.ok) deleted += ids.length;
      else if (outcome.error) errors.push(outcome.error);
    }
    this.recent.delete(key);
    return {
      action: "delete-messages",
      target: message.authorId,
      rationale: bulk ? "remove the burst of recent messages" : "remove the offending message",
      outcome: { ok: errors.length === 0, action: "delete-messages", detail: `${deleted} message(s) deleted`, ...(errors.length > 0 ? { error: errors.join("; ") } : {}) }
    };
  }

  private async warn(context: PolicyContext, message: MessageSample): Promise<ActionRecord | null> {
    if (context.policy.lockdown.suspendNonEssential && this.lockdown.isActive(message.guildId)) return null;
    if (!(await this.locks.once(`spam:warn:${message.guildId}:${message.authorId}`, context.policy.antiSpam.warnCooldownSeconds * 1000))) return null;
    const outcome = await this.gateway.sendChannelMessage(message.guildId, message.channelId, {
      content: `<@${message.authorId}>, your recent messages were flagged by the anti-spam filter. Please slow down; repeated violations lead to a temporary timeout.`,
      embeds: [],
      mentionUserIds: [message.authorId]
    });
    return { action: "warn", target: message.authorId, rationale: "first-level anti-spam warning", outcome };
  }

  private async timeout(message: MessageSample, minutes: number, reason: string): Promise<ActionRecord> {
    const guild = await this.gateway.getGuild(message.guildId);
    const member = await this.gateway.getMember(message.guildId, message.authorId);
    if (!guild || !member) return skip("timeout", message.authorId, "member unavailable");
    const capability = canTimeout(guild, member);
    if (!capability.ok) return skip("timeout", message.authorId, capability.reason ?? "cannot time out");
    if (member.communicationDisabledUntil && member.communicationDisabledUntil > this.clock.now()) return skip("timeout", message.authorId, "member is already timed out");
    const outcome = await this.gateway.timeoutMember(message.guildId, message.authorId, minutes * 60000, reason);
    return { action: "timeout", target: message.authorId, rationale: `${minutes} minute timeout after repeated spam`, outcome };
  }

  private async trackFlood(context: PolicyContext, message: MessageSample, now: number): Promise<void> {
    const flood = context.policy.antiSpam.floodSlowmode;
    if (!flood.enabled || context.policy.mode !== "automatic") return;
    const distinct = await this.counters.addDistinct(`spam:flood:${message.guildId}:${message.channelId}`, message.authorId, flood.windowSeconds * 1000, now);
    if (distinct < flood.distinctUsers) return;
    if (!(await this.locks.once(`spam:slowmode:${message.guildId}:${message.channelId}`, flood.durationMinutes * 60000))) return;
    const previous = (await this.gateway.getChannelSlowmode(message.guildId, message.channelId)) ?? 0;
    if (previous >= flood.slowmodeSeconds) return;
    const outcome = await this.gateway.setChannelSlowmode(message.guildId, message.channelId, flood.slowmodeSeconds, "Val Protection: multi-user flood detected");
    if (outcome.ok) {
      this.slowmodes.set(`${message.guildId}:${message.channelId}`, {
        guildId: message.guildId,
        channelId: message.channelId,
        previous,
        applied: flood.slowmodeSeconds,
        until: now + flood.durationMinutes * 60000
      });
    }
    await this.alerts.send({
      guildId: message.guildId,
      severity: "medium",
      title: "Channel flood",
      description: `${distinct} different members flooded ${channelRef(message.channelId)} within ${flood.windowSeconds}s. ${outcome.ok ? `Slowmode set to ${flood.slowmodeSeconds}s for ${flood.durationMinutes} minutes, then restored automatically.` : `Slowmode could not be applied: ${outcome.error ?? "unknown error"}.`}`
    });
  }

  private remember(message: MessageSample, now: number): void {
    const key = `${message.guildId}:${message.authorId}`;
    const list = (this.recent.get(key) ?? []).filter((item) => item.at >= now - 120000);
    list.push({ id: message.id, channelId: message.channelId, at: now });
    this.recent.delete(key);
    this.recent.set(key, list.slice(-15));
    if (this.recent.size > 50000) {
      const oldest = this.recent.keys().next().value;
      if (oldest !== undefined) this.recent.delete(oldest);
    }
  }
}
