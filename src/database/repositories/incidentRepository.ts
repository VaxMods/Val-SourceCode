import type { Kysely } from "kysely";
import type { Confidence, Severity } from "../../core/types.js";
import { parseJson, toJson } from "../json.js";
import type { Database, IncidentTable } from "../types.js";

export type IncidentStatus = "open" | "contained" | "needs-review" | "monitoring" | "resolved";

export interface IncidentRecord {
  id: string;
  guildId: string;
  type: string;
  severity: Severity;
  status: IncidentStatus;
  actorId: string | null;
  targetId: string | null;
  confidence: Confidence;
  summary: string;
  details: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

function toRecord(row: IncidentTable): IncidentRecord {
  return {
    id: row.id,
    guildId: row.guild_id,
    type: row.type,
    severity: row.severity as Severity,
    status: row.status as IncidentStatus,
    actorId: row.actor_id,
    targetId: row.target_id,
    confidence: row.confidence as Confidence,
    summary: row.summary,
    details: parseJson<Record<string, unknown>>(row.details_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export class IncidentRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async insert(record: IncidentRecord): Promise<void> {
    await this.db
      .insertInto("incidents")
      .values({
        id: record.id,
        guild_id: record.guildId,
        type: record.type,
        severity: record.severity,
        status: record.status,
        actor_id: record.actorId,
        target_id: record.targetId,
        confidence: record.confidence,
        summary: record.summary,
        details_json: toJson(record.details),
        created_at: record.createdAt,
        updated_at: record.updatedAt
      })
      .execute();
  }

  async update(id: string, changes: { status?: IncidentStatus; details?: Record<string, unknown>; severity?: Severity }, atIso: string): Promise<void> {
    await this.db
      .updateTable("incidents")
      .set({
        ...(changes.status ? { status: changes.status } : {}),
        ...(changes.severity ? { severity: changes.severity } : {}),
        ...(changes.details ? { details_json: toJson(changes.details) } : {}),
        updated_at: atIso
      })
      .where("id", "=", id)
      .execute();
  }

  async get(guildId: string, id: string): Promise<IncidentRecord | null> {
    const row = await this.db.selectFrom("incidents").selectAll().where("guild_id", "=", guildId).where("id", "=", id).executeTakeFirst();
    return row ? toRecord(row) : null;
  }

  async recent(guildId: string, limit: number, minSeverities?: Severity[]): Promise<IncidentRecord[]> {
    let query = this.db.selectFrom("incidents").selectAll().where("guild_id", "=", guildId);
    if (minSeverities && minSeverities.length > 0) query = query.where("severity", "in", minSeverities);
    const rows = await query.orderBy("created_at", "desc").limit(limit).execute();
    return rows.map(toRecord);
  }

  async countSince(guildId: string, sinceIso: string): Promise<number> {
    const row = await this.db
      .selectFrom("incidents")
      .select((eb) => eb.fn.countAll<number | string>().as("count"))
      .where("guild_id", "=", guildId)
      .where("created_at", ">=", sinceIso)
      .executeTakeFirst();
    return Number(row?.count ?? 0);
  }
}
