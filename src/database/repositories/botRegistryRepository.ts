import type { Kysely } from "kysely";
import { parseJson, toJson } from "../json.js";
import type { Database } from "../types.js";

export type BotStatus = "pending" | "approved" | "rejected";

export interface BotRegistryRecord {
  guildId: string;
  botId: string;
  status: BotStatus;
  addedBy: string | null;
  addedAt: string;
  reviewedBy: string | null;
  reviewedAt: string | null;
  risk: Record<string, unknown>;
}

export class BotRegistryRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async get(guildId: string, botId: string): Promise<BotRegistryRecord | null> {
    const row = await this.db.selectFrom("bot_registry").selectAll().where("guild_id", "=", guildId).where("bot_id", "=", botId).executeTakeFirst();
    if (!row) return null;
    return {
      guildId: row.guild_id,
      botId: row.bot_id,
      status: row.status as BotStatus,
      addedBy: row.added_by,
      addedAt: row.added_at,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      risk: parseJson<Record<string, unknown>>(row.risk_json, {})
    };
  }

  async list(guildId: string, status?: BotStatus): Promise<BotRegistryRecord[]> {
    let query = this.db.selectFrom("bot_registry").selectAll().where("guild_id", "=", guildId);
    if (status) query = query.where("status", "=", status);
    const rows = await query.orderBy("added_at", "desc").execute();
    return rows.map((row) => ({
      guildId: row.guild_id,
      botId: row.bot_id,
      status: row.status as BotStatus,
      addedBy: row.added_by,
      addedAt: row.added_at,
      reviewedBy: row.reviewed_by,
      reviewedAt: row.reviewed_at,
      risk: parseJson<Record<string, unknown>>(row.risk_json, {})
    }));
  }

  async upsert(record: BotRegistryRecord): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await trx.deleteFrom("bot_registry").where("guild_id", "=", record.guildId).where("bot_id", "=", record.botId).execute();
      await trx
        .insertInto("bot_registry")
        .values({
          guild_id: record.guildId,
          bot_id: record.botId,
          status: record.status,
          added_by: record.addedBy,
          added_at: record.addedAt,
          reviewed_by: record.reviewedBy,
          reviewed_at: record.reviewedAt,
          risk_json: toJson(record.risk)
        })
        .execute();
    });
  }

  async setStatus(guildId: string, botId: string, status: BotStatus, reviewedBy: string, atIso: string): Promise<boolean> {
    const result = await this.db
      .updateTable("bot_registry")
      .set({ status, reviewed_by: reviewedBy, reviewed_at: atIso })
      .where("guild_id", "=", guildId)
      .where("bot_id", "=", botId)
      .executeTakeFirst();
    return Number(result.numUpdatedRows) === 1;
  }
}
