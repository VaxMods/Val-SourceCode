import type { Logger } from "pino";
import type { ConfirmationService } from "../commands/confirmations.js";
import { errorMessage } from "../core/errors.js";
import type { SecurityKernel } from "../security/kernel.js";

export interface SchedulerOptions {
  kernel: SecurityKernel;
  confirmations: ConfirmationService;
  guildIds: () => string[];
  integrity: Map<string, { ok: boolean; checked: number; at: number; reason: string | null }>;
  logger: Logger;
}

export class Scheduler {
  private readonly timers: NodeJS.Timeout[] = [];
  private readonly running = new Set<string>();
  private stopped = false;

  constructor(private readonly options: SchedulerOptions) {}

  start(): void {
    const { kernel } = this.options;
    const global = kernel.policies.global;
    this.every("tick", global.schedulerTickSeconds * 1000, () => this.tick());
    this.every("snapshots", 5 * 60000, () => kernel.snapshots.captureDue(this.allowedGuilds()));
    this.every("retention", 60 * 60000, () => this.retention());
    this.every("integrity", global.integrityCheckIntervalMinutes * 60000, () => this.integrity());
    this.every("heartbeat", 5 * 60000, async () => this.heartbeat());
    void this.guard("integrity", () => this.integrity());
  }

  stop(): void {
    this.stopped = true;
    for (const timer of this.timers) clearInterval(timer);
    this.timers.length = 0;
  }

  async tick(): Promise<void> {
    const { kernel, confirmations } = this.options;
    const now = kernel.deps.clock.now();
    await kernel.lockdown.expireDue();
    await kernel.antiRaid.tick();
    await kernel.antiSpam.tick();
    await kernel.alerts.flushSuppressed();
    kernel.deps.counters.sweep(now);
    kernel.deps.locks.sweep(now);
    confirmations.sweep();
  }

  async retention(): Promise<void> {
    const { kernel, logger } = this.options;
    for (const guildId of this.allowedGuilds()) {
      try {
        const context = await kernel.policies.context(guildId);
        const cutoff = kernel.deps.clock.now() - context.policy.logging.retentionDays * 86400000;
        const removed = await kernel.evidence.purgeOlderThan(guildId, cutoff);
        if (removed > 0) {
          await kernel.evidence.append({ guildId, eventType: "retention.purged", severity: "info", evidence: { removed, retentionDays: context.policy.logging.retentionDays } });
        }
      } catch (error) {
        logger.error({ err: errorMessage(error), guildId }, "Retention purge failed");
      }
    }
  }

  async integrity(): Promise<void> {
    const { kernel, integrity, logger } = this.options;
    for (const guildId of this.allowedGuilds()) {
      try {
        const result = await kernel.evidence.verify(guildId);
        const previous = integrity.get(guildId);
        integrity.set(guildId, { ok: result.ok, checked: result.checked, at: kernel.deps.clock.now(), reason: result.reason });
        if (!result.ok && (previous === undefined || previous.ok)) {
          logger.error({ guildId, reason: result.reason, seq: result.brokenAtSeq }, "Evidence chain verification failed");
          await kernel.alerts.send({
            guildId,
            severity: "critical",
            title: "Evidence log integrity failure",
            description: `The tamper-evident log failed verification at record #${result.brokenAtSeq}: ${result.reason}. Records may have been modified or deleted directly in the database. Preserve the database and the JSONL mirror for investigation.`
          });
        }
      } catch (error) {
        logger.error({ err: errorMessage(error), guildId }, "Integrity verification failed to run");
      }
    }
  }

  private heartbeat(): void {
    const { kernel, logger } = this.options;
    const memory = process.memoryUsage();
    logger.info(
      {
        guilds: this.allowedGuilds().length,
        rssMiB: Math.round(memory.rss / 1048576),
        heapMiB: Math.round(memory.heapUsed / 1048576),
        degraded: kernel.deps.health.degradedComponents().map((item) => item.component)
      },
      "Heartbeat"
    );
  }

  private allowedGuilds(): string[] {
    return this.options.guildIds().filter((id) => this.options.kernel.policies.isGuildAllowed(id));
  }

  private every(name: string, intervalMs: number, task: () => Promise<void> | void): void {
    const timer = setInterval(() => void this.guard(name, task), intervalMs);
    timer.unref();
    this.timers.push(timer);
  }

  private async guard(name: string, task: () => Promise<void> | void): Promise<void> {
    if (this.stopped || this.running.has(name)) return;
    this.running.add(name);
    try {
      await task();
    } catch (error) {
      this.options.logger.error({ err: errorMessage(error), job: name }, "Scheduled job failed");
    } finally {
      this.running.delete(name);
    }
  }
}
