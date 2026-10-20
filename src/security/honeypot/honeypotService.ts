import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import type { ActionRecord } from "../../core/types.js";
import type { DiscordGateway, RoleInfo } from "../../discord/gateway.js";
import { namesOf } from "../../discord/permissions.js";
import type { AlertSink } from "../alerts/alertService.js";
import { channelRef, roleRef, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import { canEditRolePermissions, canTimeout } from "../hierarchy.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { CounterStore } from "../infra/counterStore.js";
import type { LockManager } from "../infra/lockManager.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip } from "../response/containment.js";
import type { HoneypotRoleHooks } from "../roles/roleGuard.js";

export type HoneypotKind =
  | "unauthorized-command"
  | "foreign-confirmation"
  | "decoy-role-granted"
  | "decoy-role-permission-change"
  | "decoy-channel-message"
  | "forbidden-command";

export const HONEYPOT_WEIGHTS: Record<HoneypotKind, number> = {
  "unauthorized-command": 1,
  "foreign-confirmation": 2,
  "decoy-role-granted": 2,
  "decoy-role-permission-change": 3,
  "decoy-channel-message": 1,
  "forbidden-command": 1
};

export type HoneypotVerdict = "probable-mistake" | "suspicious" | "likely-malicious";

export interface HoneypotSignal {
  guildId: string;
  userId: string;
  kind: HoneypotKind;
  context: Record<string, unknown>;
}

export class HoneypotService implements HoneypotRoleHooks {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly alerts: AlertSink,
    private readonly counters: CounterStore,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  async signal(input: HoneypotSignal): Promise<HoneypotVerdict | null> {
    const context = await this.policies.context(input.guildId);
    const settings = context.policy.honeypot;
    if (!settings.enabled) return null;
    const now = this.clock.now();
    const windowMs = settings.correlationWindowMinutes * 60000;
    const weight = HONEYPOT_WEIGHTS[input.kind];
    const score = await this.counters.hit(`honeypot:${input.guildId}:${input.userId}`, windowMs, now, weight);
    const kinds = await this.counters.addDistinct(`honeypot:kinds:${input.guildId}:${input.userId}`, input.kind, windowMs, now);
    const verdict: HoneypotVerdict =
      score >= settings.escalationScore || (kinds >= 2 && score >= 3) ? "likely-malicious" : weight >= 2 || score >= 2 ? "suspicious" : "probable-mistake";
    await this.evidence.append({
      guildId: input.guildId,
      eventType: `honeypot.${input.kind}`,
      severity: verdict === "likely-malicious" ? "high" : verdict === "suspicious" ? "medium" : "low",
      actorId: input.userId,
      confidence: "high",
      evidence: { ...input.context, correlatedScore: score, distinctKinds: kinds, verdict }
    });
    if (verdict === "probable-mistake") return verdict;
    if (verdict === "suspicious") {
      await this.alerts.send({
        guildId: input.guildId,
        severity: "medium",
        title: "Honeypot interaction",
        description: `${userRef(input.userId)} triggered a ${input.kind} trap. Correlated score ${score} over ${settings.correlationWindowMinutes} minutes; this may still be an honest mistake.`
      });
      return verdict;
    }
    if (!(await this.locks.once(`honeypot:incident:${input.guildId}:${input.userId}`, windowMs))) return verdict;
    const incident = await this.incidents.open({
      guildId: input.guildId,
      type: "honeypot.escalation",
      severity: "high",
      actorId: input.userId,
      targetId: null,
      confidence: "high",
      summary: `${userRef(input.userId)} repeatedly interacted with security traps (${kinds} different kinds, score ${score} within ${settings.correlationWindowMinutes} minutes). This pattern is unlikely to be accidental.`,
      details: { lastKind: input.kind, score, distinctKinds: kinds, context: input.context }
    });
    const actions = await this.escalate(context, input.userId);
    await this.incidents.recordActions(incident, actions);
    return verdict;
  }

  async onDecoyRoleGranted(guildId: string, recipientId: string, actorId: string | null, roleId: string): Promise<void> {
    const guild = await this.gateway.getGuild(guildId);
    const actor = actorId ? await this.gateway.getMember(guildId, actorId) : null;
    const subject = !actorId || actorId === recipientId || actor?.isBot || actorId === guild?.botUserId ? recipientId : actorId;
    await this.signal({ guildId, userId: subject, kind: "decoy-role-granted", context: { roleId, recipientId, grantedBy: actorId } });
  }

  async onDecoyRolePermissionChange(guildId: string, actorId: string | null, role: RoleInfo, previous: bigint): Promise<void> {
    const guild = await this.gateway.getGuild(guildId);
    const actions: ActionRecord[] = [];
    if (guild) {
      const capability = canEditRolePermissions(guild, role, previous);
      actions.push(
        capability.ok
          ? {
              action: "restore-decoy-permissions",
              target: role.id,
              rationale: "decoy roles must never carry privileges; restoring is done in every mode",
              outcome: await this.gateway.setRolePermissions(guildId, role.id, previous, "Val Protection: decoy role must stay without privileges")
            }
          : skip("restore-decoy-permissions", role.id, `${capability.reason}. Remove the permissions from the decoy role manually now.`)
      );
    }
    const incident = await this.incidents.open({
      guildId,
      type: "honeypot.decoy-privileged",
      severity: "critical",
      actorId,
      targetId: role.id,
      confidence: actorId ? "high" : "none",
      summary: `Decoy role ${roleRef(role.id)} received permissions (${namesOf(role.permissions & ~previous).join(", ") || "unknown"}) from ${userRef(actorId)}. Decoys must never be privileged.`,
      details: { previous: previous.toString(), current: role.permissions.toString() }
    });
    await this.incidents.recordActions(incident, actions);
    if (actorId && actorId !== guild?.botUserId) await this.signal({ guildId, userId: actorId, kind: "decoy-role-permission-change", context: { roleId: role.id } });
  }

  async onDecoyChannelMessage(guildId: string, channelId: string, userId: string, isStaff: boolean): Promise<void> {
    if (isStaff) return;
    await this.signal({ guildId, userId, kind: "decoy-channel-message", context: { channel: channelRef(channelId) } });
  }

  matchForbiddenCommand(context: PolicyContext, content: string): string | null {
    const normalized = content.trim().toLowerCase();
    if (normalized.length === 0) return null;
    return context.policy.honeypot.forbiddenCommandPatterns.find((pattern) => {
      const value = pattern.trim().toLowerCase();
      return normalized === value || normalized.startsWith(`${value} `);
    }) ?? null;
  }

  private async escalate(context: PolicyContext, userId: string): Promise<ActionRecord[]> {
    const settings = context.policy.honeypot;
    if (settings.escalationAction !== "timeout") return [skip("timeout", userId, "honeypot.escalationAction is alert")];
    if (context.policy.mode !== "automatic") return [skip("timeout", userId, "monitor mode: timeout recommended, not executed")];
    if (context.policy.securityAdminIds.includes(userId)) return [skip("timeout", userId, "security administrators are never timed out automatically")];
    const guild = await this.gateway.getGuild(context.guildId);
    const member = await this.gateway.getMember(context.guildId, userId);
    if (!guild || !member) return [skip("timeout", userId, "member unavailable")];
    if (member.roleIds.some((roleId) => context.policy.staffRoleIds.includes(roleId))) return [skip("timeout", userId, "staff members are never timed out by the honeypot")];
    const capability = canTimeout(guild, member);
    if (!capability.ok) return [skip("timeout", userId, capability.reason ?? "cannot time out")];
    const outcome = await this.gateway.timeoutMember(context.guildId, userId, settings.timeoutMinutes * 60000, "Val Protection: repeated interaction with security traps");
    this.logger.warn({ guildId: context.guildId, userId }, "Honeypot escalation timeout applied");
    return [{ action: "timeout", target: userId, rationale: "repeated, correlated interaction with security traps", outcome }];
  }
}
