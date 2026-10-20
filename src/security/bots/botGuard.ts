import { AuditLogEvent } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { ActionRecord, Confidence } from "../../core/types.js";
import type { BotRegistryRepository } from "../../database/repositories/botRegistryRepository.js";
import { auditConfidence, type AuditEvent } from "../../discord/auditEvent.js";
import type { DiscordGateway } from "../../discord/gateway.js";
import { ADMINISTRATOR, dangerousBits, namesOf } from "../../discord/permissions.js";
import { userRef } from "../alerts/format.js";
import type { EvidenceSink } from "../evidence/evidenceLog.js";
import type { IncidentService } from "../incidents/incidentService.js";
import type { CounterStore } from "../infra/counterStore.js";
import type { LockManager } from "../infra/lockManager.js";
import type { LockdownService } from "../lockdown/lockdownService.js";
import type { PolicyContext, PolicyService } from "../policy/policyService.js";
import { skip, type ContainmentResponder } from "../response/containment.js";

export interface BotRisk {
  score: number;
  level: "low" | "medium" | "high";
  factors: string[];
}

export interface BotAddedInput {
  guildId: string;
  botId: string;
  adderId: string | null;
  confidence: Confidence;
}

export class BotGuard {
  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly registry: BotRegistryRepository,
    private readonly incidents: IncidentService,
    private readonly evidence: EvidenceSink,
    private readonly responder: ContainmentResponder,
    private readonly lockdown: LockdownService,
    private readonly counters: CounterStore,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger
  ) {}

  async onAuditEvent(event: AuditEvent): Promise<void> {
    if (event.actionType !== AuditLogEvent.BotAdd || !event.targetId) return;
    await this.onBotAdded({ guildId: event.guildId, botId: event.targetId, adderId: event.executorId, confidence: auditConfidence(event) });
  }

  async onBotJoined(guildId: string, botId: string): Promise<void> {
    const context = await this.policies.context(guildId);
    await this.clock.sleep(context.policy.roleProtection.correlationDelayMs);
    const entries = await this.gateway.findAuditEvents(guildId, AuditLogEvent.BotAdd, 10);
    const match = entries.find((entry) => entry.targetId === botId && this.clock.now() - entry.createdAt < 120000);
    await this.onBotAdded({
      guildId,
      botId,
      adderId: match?.executorId ?? null,
      confidence: match?.executorId ? "high" : "none"
    });
  }

  async onBotAdded(input: BotAddedInput): Promise<{ risk: BotRisk; actions: ActionRecord[] } | null> {
    if (!(await this.locks.once(`bot-added:${input.guildId}:${input.botId}`, 300000))) return null;
    const context = await this.policies.context(input.guildId);
    const guild = await this.gateway.getGuild(input.guildId);
    if (!guild || input.botId === guild.botUserId) return null;
    const now = this.clock.now();
    const nowIso = new Date(now).toISOString();
    if (this.policies.isApprovedBot(context, input.botId)) {
      await this.saveRegistry(input, "approved", { approvedBy: "policy" }, nowIso);
      await this.evidence.append({ guildId: input.guildId, eventType: "bot.added.approved", severity: "info", actorId: input.adderId, targetId: input.botId, confidence: input.confidence });
      return { risk: { score: 0, level: "low", factors: ["bot is on the approved list"] }, actions: [] };
    }
    const recentAdds = await this.counters.hit(`bots:added:${input.guildId}`, 600000, now);
    const risk = await this.assess(context, guild.ownerId, input, recentAdds);
    await this.saveRegistry(input, "pending", { ...risk }, nowIso);
    const adderAuthorized = this.isAuthorizedAdder(context, guild.ownerId, input.adderId);
    const incident = await this.incidents.open({
      guildId: input.guildId,
      type: "bot.unapproved",
      severity: risk.level === "high" ? "high" : "medium",
      actorId: input.adderId,
      targetId: input.botId,
      confidence: input.confidence,
      summary: `Bot ${userRef(input.botId)} was added by ${userRef(input.adderId)} and is not on the approved list. It is in logical quarantine (pending review). Not being approved does not mean it is malicious. Risk: ${risk.level} (${risk.score}). Approve it with /security whitelist add or remove it if unexpected.`,
      details: { risk, adderAuthorized, recentBotAdds: recentAdds },
      fields: [{ name: "Risk factors", value: risk.factors.join("\n") || "none", inline: false }]
    });
    const actions: ActionRecord[] = [];
    const bots = context.policy.bots;
    if (bots.unapprovedAction !== "kick") {
      actions.push(skip("kick-bot", input.botId, "recommendation only: bots.unapprovedAction is alert"));
    } else if (context.policy.mode !== "automatic") {
      actions.push(skip("kick-bot", input.botId, "monitor mode: removal recommended, not executed"));
    } else if (bots.kickOnlyWhenAdderUnauthorized && adderAuthorized) {
      actions.push(skip("kick-bot", input.botId, "added by an authorized person; awaiting manual approval"));
    } else if (bots.kickOnlyWhenAdderUnauthorized && input.confidence !== "high") {
      actions.push(skip("kick-bot", input.botId, "the person who added the bot is not identified with high confidence"));
    } else {
      actions.push(await this.responder.kickBot(input.guildId, input.botId, `Val Protection: unapproved bot added by an unauthorized account (incident ${incident.id})`));
    }
    await this.incidents.recordActions(incident, actions, { statusOverride: actions.some((item) => item.outcome.ok) ? "contained" : "needs-review" });
    return { risk, actions };
  }

  async approve(guildId: string, botId: string, reviewer: string): Promise<void> {
    try {
      const existing = await this.registry.get(guildId, botId);
      if (existing) await this.registry.setStatus(guildId, botId, "approved", reviewer, new Date(this.clock.now()).toISOString());
    } catch (error) {
      this.logger.error({ err: errorMessage(error) }, "Could not update bot registry");
    }
  }

  private isAuthorizedAdder(context: PolicyContext, ownerId: string, adderId: string | null): boolean {
    if (!adderId) return false;
    return adderId === ownerId || context.policy.securityAdminIds.includes(adderId) || context.policy.bots.authorizedAdderIds.includes(adderId);
  }

  private async assess(context: PolicyContext, ownerId: string, input: BotAddedInput, recentAdds: number): Promise<BotRisk> {
    const factors: string[] = [];
    let score = 0;
    if (!input.adderId) {
      score += 15;
      factors.push("the account that added the bot is unknown");
    } else if (!this.isAuthorizedAdder(context, ownerId, input.adderId)) {
      score += 35;
      factors.push("added by an account that is not an authorized bot adder");
    }
    const member = await this.gateway.getMember(input.guildId, input.botId);
    if (member) {
      if ((member.permissions & ADMINISTRATOR) === ADMINISTRATOR) {
        score += 30;
        factors.push("bot has Administrator");
      } else {
        const dangerous = dangerousBits(member.permissions, context.dangerousMask);
        if (dangerous !== 0n) {
          score += 20;
          factors.push(`bot holds dangerous permissions: ${namesOf(dangerous).join(", ")}`);
        }
      }
    }
    if (this.lockdown.isActive(input.guildId)) {
      score += 20;
      factors.push("added while the server is in lockdown");
    }
    if (recentAdds >= 2) {
      score += 20;
      factors.push(`${recentAdds} bots added in the last 10 minutes`);
    }
    const capped = Math.min(100, score);
    return { score: capped, level: capped >= 60 ? "high" : capped >= 30 ? "medium" : "low", factors };
  }

  private async saveRegistry(input: BotAddedInput, status: "pending" | "approved", risk: Record<string, unknown>, nowIso: string): Promise<void> {
    try {
      await this.registry.upsert({
        guildId: input.guildId,
        botId: input.botId,
        status,
        addedBy: input.adderId,
        addedAt: nowIso,
        reviewedBy: status === "approved" ? "policy" : null,
        reviewedAt: status === "approved" ? nowIso : null,
        risk
      });
    } catch (error) {
      this.logger.error({ err: errorMessage(error) }, "Could not persist bot registry entry");
    }
  }
}
