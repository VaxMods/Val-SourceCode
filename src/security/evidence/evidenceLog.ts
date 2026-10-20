import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Logger } from "pino";
import type { Clock } from "../../core/clock.js";
import { errorMessage } from "../../core/errors.js";
import type { HealthMonitor } from "../../core/health.js";
import { redactSecrets, redactString } from "../../core/redact.js";
import { stableStringify } from "../../core/stableJson.js";
import type { Confidence, Severity } from "../../core/types.js";
import type { EventRepository, StoredEvent } from "../../database/repositories/eventRepository.js";
import type { LockManager } from "../infra/lockManager.js";

export const GENESIS_HASH = "0".repeat(64);

export interface EvidenceInput {
  guildId: string;
  eventType: string;
  severity: Severity;
  actorId?: string | null;
  targetId?: string | null;
  confidence?: Confidence;
  action?: string | null;
  actionResult?: string | null;
  evidence?: Record<string, unknown>;
  error?: string | null;
  incidentId?: string | null;
  occurredAt?: number;
}

export interface VerificationResult {
  guildId: string;
  ok: boolean;
  checked: number;
  firstSeq: number | null;
  lastSeq: number | null;
  brokenAtSeq: number | null;
  reason: string | null;
}

export interface EvidenceSink {
  append(input: EvidenceInput): Promise<StoredEvent | null>;
}

export class EvidenceLog implements EvidenceSink {
  private readonly heads = new Map<string, { seq: number; hash: string }>();

  constructor(
    private readonly repo: EventRepository,
    private readonly key: Buffer,
    private readonly locks: LockManager,
    private readonly clock: Clock,
    private readonly logger: Logger,
    private readonly health: HealthMonitor,
    private readonly files: { mirrorPath: string | null; fallbackPath: string | null }
  ) {
    for (const target of [files.mirrorPath, files.fallbackPath]) {
      if (target) fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    }
  }

  static hashOf(key: Buffer, prevHash: string, payload: Record<string, unknown>): string {
    return crypto.createHmac("sha256", key).update(prevHash).update("\n").update(stableStringify(payload)).digest("hex");
  }

  async append(input: EvidenceInput): Promise<StoredEvent | null> {
    const occurredAt = new Date(input.occurredAt ?? this.clock.now()).toISOString();
    const base = {
      guildId: input.guildId,
      occurredAt,
      eventType: input.eventType,
      severity: input.severity,
      actorId: input.actorId ?? null,
      targetId: input.targetId ?? null,
      confidence: input.confidence ?? "none",
      action: input.action ?? null,
      actionResult: input.actionResult ? redactString(input.actionResult).slice(0, 2000) : null,
      evidence: redactSecrets(input.evidence ?? {}),
      error: input.error ? redactString(input.error).slice(0, 2000) : null,
      incidentId: input.incidentId ?? null
    };
    try {
      const stored = await this.locks.withLock(`evidence:${input.guildId}`, 10000, () => this.insertChained(base));
      if (this.health.healthy("evidence-store")) this.logger.info("Evidence store recovered");
      await this.writeLine(this.files.mirrorPath, stored);
      return stored;
    } catch (error) {
      if (this.health.degraded("evidence-store", errorMessage(error))) {
        this.logger.error({ err: errorMessage(error) }, "Evidence store unavailable; writing to fallback file");
      }
      await this.writeLine(this.files.fallbackPath, { ...base, persisted: false, failure: errorMessage(error) });
      return null;
    }
  }

  async verify(guildId: string, pageSize = 500): Promise<VerificationResult> {
    const anchor = await this.repo.anchor(guildId);
    let expectedPrev = anchor?.hash ?? GENESIS_HASH;
    let expectedSeq = (anchor?.seq ?? 0) + 1;
    let checked = 0;
    let firstSeq: number | null = null;
    let lastSeq: number | null = null;
    let cursor = anchor?.seq ?? 0;
    for (;;) {
      const page = await this.repo.page(guildId, cursor, pageSize);
      if (page.length === 0) break;
      for (const event of page) {
        firstSeq ??= event.seq;
        if (event.seq !== expectedSeq) {
          return { guildId, ok: false, checked, firstSeq, lastSeq, brokenAtSeq: event.seq, reason: `sequence gap: expected ${expectedSeq}, found ${event.seq}` };
        }
        if (event.prevHash !== expectedPrev) {
          return { guildId, ok: false, checked, firstSeq, lastSeq, brokenAtSeq: event.seq, reason: "previous hash does not match the chain" };
        }
        const recomputed = EvidenceLog.hashOf(this.key, event.prevHash, payloadOf(event));
        if (!crypto.timingSafeEqual(Buffer.from(recomputed, "hex"), Buffer.from(event.hash, "hex"))) {
          return { guildId, ok: false, checked, firstSeq, lastSeq, brokenAtSeq: event.seq, reason: "record content does not match its HMAC" };
        }
        expectedPrev = event.hash;
        expectedSeq += 1;
        lastSeq = event.seq;
        checked += 1;
      }
      cursor = page[page.length - 1]?.seq ?? cursor;
    }
    return { guildId, ok: true, checked, firstSeq, lastSeq, brokenAtSeq: null, reason: null };
  }

  async purgeOlderThan(guildId: string, cutoffMs: number): Promise<number> {
    const cutoffIso = new Date(cutoffMs).toISOString();
    return this.locks.withLock(`evidence:${guildId}`, 30000, async () => {
      const last = await this.repo.lastSeqBefore(guildId, cutoffIso);
      if (!last) return 0;
      const head = await this.repo.head(guildId);
      if (head && head.seq === last.seq) return 0;
      const removed = await this.repo.purgeThrough(guildId, last.seq, {
        guildId,
        seq: last.seq,
        hash: last.hash,
        purgedAt: new Date(this.clock.now()).toISOString(),
        purgedCount: 0
      });
      this.logger.info({ guildId, removed, throughSeq: last.seq }, "Evidence retention purge completed");
      return removed;
    });
  }

  async headOf(guildId: string): Promise<{ seq: number; hash: string } | null> {
    return this.repo.head(guildId);
  }

  private async insertChained(base: Omit<StoredEvent, "seq" | "prevHash" | "hash">): Promise<StoredEvent> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      let head = this.heads.get(base.guildId);
      if (!head || attempt > 0) {
        const fromDb = await this.repo.head(base.guildId);
        const anchor = fromDb ? null : await this.repo.anchor(base.guildId);
        head = fromDb ?? (anchor ? { seq: anchor.seq, hash: anchor.hash } : { seq: 0, hash: GENESIS_HASH });
      }
      const seq = head.seq + 1;
      const payload = payloadOf({ ...base, seq });
      const hash = EvidenceLog.hashOf(this.key, head.hash, payload);
      const stored: StoredEvent = { ...base, seq, prevHash: head.hash, hash };
      try {
        await this.repo.insert(stored);
        this.heads.set(base.guildId, { seq, hash });
        return stored;
      } catch (error) {
        this.heads.delete(base.guildId);
        if (attempt === 1) throw error;
      }
    }
    throw new Error("Unreachable evidence insertion state");
  }

  private async writeLine(target: string | null, record: unknown): Promise<void> {
    if (!target) return;
    try {
      await fs.promises.appendFile(target, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
    } catch (error) {
      this.logger.error({ err: errorMessage(error), target }, "Could not write evidence file");
    }
  }
}

export function payloadOf(event: Omit<StoredEvent, "prevHash" | "hash">): Record<string, unknown> {
  return {
    seq: event.seq,
    guildId: event.guildId,
    occurredAt: event.occurredAt,
    eventType: event.eventType,
    severity: event.severity,
    actorId: event.actorId,
    targetId: event.targetId,
    confidence: event.confidence,
    action: event.action,
    actionResult: event.actionResult,
    evidence: event.evidence,
    error: event.error,
    incidentId: event.incidentId
  };
}
