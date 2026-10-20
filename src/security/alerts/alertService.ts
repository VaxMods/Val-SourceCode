import fs from "node:fs";
import path from "node:path";
import type { APIEmbed } from "discord.js";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { HealthMonitor } from "../../core/health.js";
import { atLeastSeverity, type Severity } from "../../core/types.js";
import type { DiscordGateway, OutgoingFile } from "../../discord/gateway.js";
import type { PolicyService } from "../policy/policyService.js";
import { buildEmbed, type AlertContent } from "./format.js";

export interface AlertRequest extends Omit<AlertContent, "timestamp"> {
  guildId: string;
  files?: OutgoingFile[];
}

export type AlertDelivery = "channel" | "webhook" | "file" | "suppressed" | "none";

export interface AlertSink {
  send(request: AlertRequest): Promise<AlertDelivery>;
}

export interface FallbackTransport {
  postWebhook(url: string, body: unknown): Promise<boolean>;
}

export const fetchTransport: FallbackTransport = {
  async postWebhook(url, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(`${url}?wait=false`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal
      });
      return response.ok;
    } finally {
      clearTimeout(timer);
    }
  }
};

export class AlertService implements AlertSink {
  private readonly windows = new Map<string, { start: number; count: number; suppressed: number }>();

  constructor(
    private readonly gateway: DiscordGateway,
    private readonly policies: PolicyService,
    private readonly clock: Clock,
    private readonly logger: Logger,
    private readonly health: HealthMonitor,
    private readonly fallback: { webhookUrl: string | null; filePath: string | null; transport: FallbackTransport },
    private readonly maxPerMinute = 20
  ) {
    if (fallback.filePath) fs.mkdirSync(path.dirname(fallback.filePath), { recursive: true, mode: 0o700 });
  }

  async send(request: AlertRequest): Promise<AlertDelivery> {
    const now = this.clock.now();
    const embed = buildEmbed({ ...request, timestamp: now });
    if (!atLeastSeverity(request.severity, "high") && this.throttled(request.guildId, now)) return "suppressed";
    const context = await this.policies.context(request.guildId);
    const channelId = context.policy.alertChannelId;
    if (channelId) {
      const mention = context.policy.alertPingRoleId && atLeastSeverity(request.severity, "high") ? [context.policy.alertPingRoleId] : [];
      const outcome = await this.gateway.sendChannelMessage(request.guildId, channelId, {
        content: mention.length > 0 ? mention.map((id) => `<@&${id}>`).join(" ") : undefined,
        embeds: [embed],
        mentionRoleIds: mention,
        files: request.files
      });
      if (outcome.ok) {
        if (this.health.healthy(`alerts:${request.guildId}`)) this.logger.info({ guildId: request.guildId }, "Alert channel reachable again");
        return "channel";
      }
      if (this.health.degraded(`alerts:${request.guildId}`, outcome.error ?? "send failed")) {
        this.logger.warn({ guildId: request.guildId, err: outcome.error }, "Alert channel unavailable; using fallback");
      }
    }
    return this.sendFallback(request.guildId, request.severity, embed);
  }

  async sendFallback(guildId: string, severity: Severity, embed: APIEmbed): Promise<AlertDelivery> {
    if (this.fallback.webhookUrl) {
      try {
        const ok = await this.fallback.transport.postWebhook(this.fallback.webhookUrl, {
          username: "Val Protection",
          content: `Fallback alert for guild ${guildId}`,
          embeds: [embed],
          allowed_mentions: { parse: [] }
        });
        if (ok) return "webhook";
      } catch (error) {
        this.logger.error({ err: errorMessage(error) }, "Fallback webhook delivery failed");
      }
    }
    if (this.fallback.filePath) {
      try {
        await fs.promises.appendFile(
          this.fallback.filePath,
          `${JSON.stringify({ at: new Date(this.clock.now()).toISOString(), guildId, severity, embed })}\n`,
          { encoding: "utf8", mode: 0o600 }
        );
        return "file";
      } catch (error) {
        this.logger.error({ err: errorMessage(error) }, "Fallback alert file write failed");
      }
    }
    this.logger.error({ guildId, severity, title: embed.title }, "Alert could not be delivered by any channel");
    return "none";
  }

  async flushSuppressed(): Promise<void> {
    const now = this.clock.now();
    for (const [guildId, window] of this.windows) {
      if (now - window.start < 60000) continue;
      this.windows.delete(guildId);
      if (window.suppressed > 0) {
        await this.send({
          guildId,
          severity: "medium",
          title: "Alerts throttled",
          description: `${window.suppressed} lower-severity alerts were suppressed in the last minute to avoid flooding. All of them are recorded in the evidence log (/security logs).`
        });
      }
    }
  }

  private throttled(guildId: string, now: number): boolean {
    const window = this.windows.get(guildId);
    if (!window || now - window.start >= 60000) {
      this.windows.set(guildId, { start: now, count: 1, suppressed: window?.suppressed ?? 0 });
      return false;
    }
    window.count += 1;
    if (window.count > this.maxPerMinute) {
      window.suppressed += 1;
      return true;
    }
    return false;
  }
}
