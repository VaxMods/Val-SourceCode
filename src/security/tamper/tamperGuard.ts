import { AuditLogEvent } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { auditConfidence, type AuditEvent } from "../../discord/auditEvent.js";
import type { DiscordGateway, RoleInfo } from "../../discord/gateway.js";
import { REQUIRED_BOT_PERMISSIONS, bitsOf, namesOf } from "../../discord/permissions.js";
import type { AlertService } from "../alerts/alertService.js";
import { buildEmbed } from "../alerts/format.js";
import { channelRef, roleRef, userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { LockManager } from "../infra/lockManager.js";
import type { PolicyService } from "../policy/policyService.js";

export class TamperGuard {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly alerts: AlertService,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  async onAuditEvent(event: AuditEvent): Promise<void> {
    const context = await this.policies.context(event.guildId);
    const guild = await this.gateway.getGuild(event.guildId);
    if (!guild || event.executorId === guild.botUserId) return;
    const alertChannelId = context.policy.alertChannelId;
    switch (event.actionType) {
      case AuditLogEvent.ChannelDelete:
        if (alertChannelId && event.targetId === alertChannelId) {
          await this.incidents.open({
            guildId: event.guildId,
            type: "tamper.alert-channel-deleted",
            severity: "critical",
            actorId: event.executorId,
            targetId: event.targetId,
            confidence: auditConfidence(event),
            status: "needs-review",
            summary: `${userRef(event.executorId)} deleted the security alert channel. Alerts now go to the fallback webhook and local files until alertChannelId is updated.`,
            details: { auditEntryId: event.id }
          });
        }
        return;
      case AuditLogEvent.MessageDelete:
      case AuditLogEvent.MessageBulkDelete: {
        const channelId = event.actionType === AuditLogEvent.MessageBulkDelete ? event.targetId : (event.extra.channelId as string | undefined) ?? null;
        if (!alertChannelId || channelId !== alertChannelId) return;
        if (event.actionType === AuditLogEvent.MessageDelete && event.targetId !== guild.botUserId) return;
        await this.logTampering(event.guildId, event.executorId, alertChannelId, Number(event.extra.count ?? 1), auditConfidence(event));
        return;
      }
      case AuditLogEvent.RoleDelete: {
        const roleId = event.targetId;
        if (!roleId) return;
        const watched = [
          ...context.protectedRoles.keys(),
          ...(context.policy.antiRaid.quarantineRoleId ? [context.policy.antiRaid.quarantineRoleId] : []),
          ...context.policy.honeypot.decoyRoleIds
        ];
        if (!watched.includes(roleId)) return;
        await this.incidents.open({
          guildId: event.guildId,
          type: "tamper.security-role-deleted",
          severity: "high",
          actorId: event.executorId,
          targetId: roleId,
          confidence: auditConfidence(event),
          status: "needs-review",
          summary: `${userRef(event.executorId)} deleted a role used by Val Protection (${roleId}). Related protections are degraded until the configuration is updated.`,
          details: { auditEntryId: event.id }
        });
        return;
      }
      default:
        return;
    }
  }

  async onBulkDeleteWithoutAudit(guildId: string, channelId: string, count: number): Promise<void> {
    const context = await this.policies.context(guildId);
    if (context.policy.alertChannelId !== channelId) return;
    await this.clock.sleep(3000);
    await this.logTampering(guildId, null, channelId, count, "none");
  }

  async onBotRoleChanged(guildId: string, role: RoleInfo, oldPermissions: bigint, oldPosition: number): Promise<void> {
    const guild = await this.gateway.getGuild(guildId);
    if (!guild) return;
    const lost = oldPermissions & ~role.permissions & bitsOf(REQUIRED_BOT_PERMISSIONS);
    const demoted = role.position < oldPosition;
    if (lost === 0n && !demoted) return;
    if (!(await this.locks.once(`tamper:bot-role:${guildId}:${role.id}:${lost}:${role.position}`, 600000))) return;
    await this.incidents.open({
      guildId,
      type: "tamper.bot-permissions-reduced",
      severity: "high",
      actorId: null,
      targetId: role.id,
      confidence: "medium",
      status: "needs-review",
      summary: `Val Protection's role ${roleRef(role.id)} was ${lost !== 0n ? `stripped of ${namesOf(lost).join(", ")}` : ""}${lost !== 0n && demoted ? " and " : ""}${demoted ? `moved down (position ${oldPosition} → ${role.position})` : ""}. Some protections are now degraded. Check the audit log for the author.`,
      details: { lost: namesOf(lost), oldPosition, newPosition: role.position }
    });
  }

  async onBotRolesRemoved(guildId: string, removedRoleIds: string[]): Promise<void> {
    if (removedRoleIds.length === 0) return;
    await this.incidents.open({
      guildId,
      type: "tamper.bot-roles-removed",
      severity: "high",
      actorId: null,
      targetId: null,
      confidence: "medium",
      status: "needs-review",
      summary: `Roles were removed from Val Protection: ${removedRoleIds.map((id) => roleRef(id)).join(", ")}. Protections relying on them may be degraded.`,
      details: { removedRoleIds }
    });
  }

  async onBotRemoved(guildId: string, guildName: string): Promise<void> {
    this.logger.error({ guildId, guildName }, "Val Protection was removed from a guild or lost access");
    await this.evidence.append({ guildId, eventType: "tamper.bot-removed", severity: "critical", evidence: { guildName } });
    await this.alerts.sendFallback(
      guildId,
      "critical",
      buildEmbed({
        severity: "critical",
        title: "Val Protection removed from server",
        description: `Val Protection was removed from "${guildName}" (${guildId}) or lost access to it. No further protection is active there. If this was not planned, treat it as a possible takeover.`,
        timestamp: this.clock.now()
      })
    );
  }

  private async logTampering(guildId: string, actorId: string | null, channelId: string, count: number, confidence: "high" | "medium" | "none"): Promise<void> {
    if (!(await this.locks.once(`tamper:alert-messages:${guildId}`, 60000))) return;
    await this.incidents.open({
      guildId,
      type: "tamper.alert-messages-deleted",
      severity: "high",
      actorId,
      targetId: channelId,
      confidence,
      status: "needs-review",
      summary: `${actorId ? userRef(actorId) : "Someone"} deleted ${count} Val Protection message(s) in ${channelRef(channelId)}. The tamper-evident evidence log is unaffected; use /security logs to review the full history.`,
      details: { count }
    });
  }
}
