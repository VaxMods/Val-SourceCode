import type { Kysely } from "kysely";
import type { Confidence, Severity } from "../../core/types.js";
import { parseJson, toJson } from "../json.js";
import type { Database, SecurityEventTable } from "../types.js";

export interface StoredEvent {
  guildId: string;
  seq: number;
  occurredAt: string;
  eventType: string;
  severity: Severity;
  actorId: string | null;
  targetId: string | null;
  confidence: Confidence;
  action: string | null;
  actionResult: string | null;
  evidence: Record<string, unknown>;
  error: string | null;
  incidentId: string | null;
  prevHash: string;
  hash: string;
}

export interface LogAnchor {
  guildId: string;
  seq: number;
  hash: string;
  purgedAt: string;
  purgedCount: number;
}

function toEvent(row: SecurityEventTable): StoredEvent {
  return {
    guildId: row.guild_id,
    seq: Number(row.seq),
    occurredAt: row.occurred_at,
    eventType: row.event_type,
    severity: row.severity as Severity,
    actorId: row.actor_id,
    targetId: row.target_id,
    confidence: row.confidence as Confidence,
    action: row.action,
    actionResult: row.action_result,
    evidence: parseJson<Record<string, unknown>>(row.evidence_json, {}),
    error: row.error,
    incidentId: row.incident_id,
    prevHash: row.prev_hash,
    hash: row.hash
  };
}

export class EventRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async head(guildId: string): Promise<{ seq: number; hash: string } | null> {
    const row = await this.db
      .selectFrom("security_events")
      .select(["seq", "hash"])
      .where("guild_id", "=", guildId)
      .orderBy("seq", "desc")
      .limit(1)
      .executeTakeFirst();
    return row ? { seq: Number(row.seq), hash: row.hash } : null;
  }

  async insert(event: StoredEvent): Promise<void> {
    await this.db
      .insertInto("security_events")
      .values({
        guild_id: event.guildId,
        seq: event.seq,
        occurred_at: event.occurredAt,
        event_type: event.eventType,
        severity: event.severity,
        actor_id: event.actorId,
        target_id: event.targetId,
        confidence: event.confidence,
        action: event.action,
        action_result: event.actionResult,
        evidence_json: toJson(event.evidence),
        error: event.error,
        incident_id: event.incidentId,
        prev_hash: event.prevHash,
        hash: event.hash
      })
      .execute();
  }

  async page(guildId: string, afterSeq: number, limit: number): Promise<StoredEvent[]> {
    const rows = await this.db
      .selectFrom("security_events")
      .selectAll()
      .where("guild_id", "=", guildId)
      .where("seq", ">", afterSeq)
      .orderBy("seq", "asc")
      .limit(limit)
      .execute();
    return rows.map(toEvent);
  }

  async recent(guildId: string, limit: number, severities?: Severity[]): Promise<StoredEvent[]> {
    let query = this.db.selectFrom("security_events").selectAll().where("guild_id", "=", guildId);
    if (severities && severities.length > 0) query = query.where("severity", "in", severities);
    const rows = await query.orderBy("seq", "desc").limit(limit).execute();
    return rows.map(toEvent);
  }

  async forIncident(guildId: string, incidentId: string, limit: number): Promise<StoredEvent[]> {
    const rows = await this.db
      .selectFrom("security_events")
      .selectAll()
      .where("guild_id", "=", guildId)
      .where("incident_id", "=", incidentId)
      .orderBy("seq", "asc")
      .limit(limit)
      .execute();
    return rows.map(toEvent);
  }

  async lastSeqBefore(guildId: string, beforeIso: string): Promise<{ seq: number; hash: string } | null> {
    const row = await this.db
      .selectFrom("security_events")
      .select(["seq", "hash"])
      .where("guild_id", "=", guildId)
      .where("occurred_at", "<", beforeIso)
      .orderBy("seq", "desc")
      .limit(1)
      .executeTakeFirst();
    return row ? { seq: Number(row.seq), hash: row.hash } : null;
  }

  async purgeThrough(guildId: string, seq: number, anchor: LogAnchor): Promise<number> {
    return this.db.transaction().execute(async (trx) => {
      const result = await trx.deleteFrom("security_events").where("guild_id", "=", guildId).where("seq", "<=", seq).executeTakeFirst();
      await trx.deleteFrom("log_anchors").where("guild_id", "=", guildId).execute();
      await trx
        .insertInto("log_anchors")
        .values({ guild_id: anchor.guildId, seq: anchor.seq, hash: anchor.hash, purged_at: anchor.purgedAt, purged_count: anchor.purgedCount })
        .execute();
      return Number(result.numDeletedRows);
    });
  }

  async anchor(guildId: string): Promise<LogAnchor | null> {
    const row = await this.db.selectFrom("log_anchors").selectAll().where("guild_id", "=", guildId).executeTakeFirst();
    return row ? { guildId: row.guild_id, seq: Number(row.seq), hash: row.hash, purgedAt: row.purged_at, purgedCount: Number(row.purged_count) } : null;
  }

  async latestOfType(guildId: string, eventType: string): Promise<StoredEvent | null> {
    const row = await this.db
      .selectFrom("security_events")
      .selectAll()
      .where("guild_id", "=", guildId)
      .where("event_type", "=", eventType)
      .orderBy("seq", "desc")
      .limit(1)
      .executeTakeFirst();
    return row ? toEvent(row) : null;
  }

  async guildIds(): Promise<string[]> {
    const rows = await this.db.selectFrom("security_events").select("guild_id").distinct().execute();
    return rows.map((row) => row.guild_id);
  }
}
