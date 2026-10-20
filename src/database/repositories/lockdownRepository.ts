import type { Kysely } from "kysely";
import { parseJson, toJson } from "../json.js";
import type { Database, LockdownTable } from "../types.js";

export interface LockdownPreviousState {
  verificationLevel: number | null;
  appliedVerificationLevel: number | null;
  invitesPausedByUs: boolean;
  pauseMethod: "incident-actions" | "feature" | null;
}

export interface LockdownRecord {
  guildId: string;
  active: boolean;
  reason: string;
  triggeredBy: string;
  startedAt: string;
  expiresAt: string;
  endedAt: string | null;
  endedBy: string | null;
  previousState: LockdownPreviousState;
}

function toRecord(row: LockdownTable): LockdownRecord {
  return {
    guildId: row.guild_id,
    active: Number(row.active) === 1,
    reason: row.reason,
    triggeredBy: row.triggered_by,
    startedAt: row.started_at,
    expiresAt: row.expires_at,
    endedAt: row.ended_at,
    endedBy: row.ended_by,
    previousState: parseJson<LockdownPreviousState>(row.previous_state_json, {
      verificationLevel: null,
      appliedVerificationLevel: null,
      invitesPausedByUs: false,
      pauseMethod: null
    })
  };
}

export class LockdownRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async get(guildId: string): Promise<LockdownRecord | null> {
    const row = await this.db.selectFrom("lockdowns").selectAll().where("guild_id", "=", guildId).executeTakeFirst();
    return row ? toRecord(row) : null;
  }

  async listActive(): Promise<LockdownRecord[]> {
    const rows = await this.db.selectFrom("lockdowns").selectAll().where("active", "=", 1).execute();
    return rows.map(toRecord);
  }

  async start(record: LockdownRecord): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await trx.deleteFrom("lockdowns").where("guild_id", "=", record.guildId).execute();
      await trx
        .insertInto("lockdowns")
        .values({
          guild_id: record.guildId,
          active: 1,
          reason: record.reason,
          triggered_by: record.triggeredBy,
          started_at: record.startedAt,
          expires_at: record.expiresAt,
          ended_at: null,
          ended_by: null,
          previous_state_json: toJson(record.previousState)
        })
        .execute();
    });
  }

  async updateState(guildId: string, state: LockdownPreviousState): Promise<void> {
    await this.db.updateTable("lockdowns").set({ previous_state_json: toJson(state) }).where("guild_id", "=", guildId).execute();
  }

  async end(guildId: string, endedBy: string, atIso: string): Promise<boolean> {
    const result = await this.db
      .updateTable("lockdowns")
      .set({ active: 0, ended_at: atIso, ended_by: endedBy })
      .where("guild_id", "=", guildId)
      .where("active", "=", 1)
      .executeTakeFirst();
    return Number(result.numUpdatedRows) === 1;
  }
}
