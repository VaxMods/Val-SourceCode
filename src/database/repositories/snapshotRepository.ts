import type { Kysely } from "kysely";
import { parseJson, toJson } from "../json.js";
import type { Database } from "../types.js";

export interface SnapshotSummary {
  id: string;
  guildId: string;
  createdAt: string;
  hash: string;
  roleCount: number;
  channelCount: number;
}

export class SnapshotRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async insert(summary: SnapshotSummary, data: unknown): Promise<void> {
    await this.db
      .insertInto("guild_snapshots")
      .values({
        id: summary.id,
        guild_id: summary.guildId,
        created_at: summary.createdAt,
        data_json: toJson(data),
        hash: summary.hash,
        role_count: summary.roleCount,
        channel_count: summary.channelCount
      })
      .execute();
  }

  async list(guildId: string, limit: number): Promise<SnapshotSummary[]> {
    const rows = await this.db
      .selectFrom("guild_snapshots")
      .select(["id", "guild_id", "created_at", "hash", "role_count", "channel_count"])
      .where("guild_id", "=", guildId)
      .orderBy("created_at", "desc")
      .limit(limit)
      .execute();
    return rows.map((row) => ({
      id: row.id,
      guildId: row.guild_id,
      createdAt: row.created_at,
      hash: row.hash,
      roleCount: Number(row.role_count),
      channelCount: Number(row.channel_count)
    }));
  }

  async load<T>(guildId: string, id: string): Promise<{ summary: SnapshotSummary; data: T; raw: string } | null> {
    const row = await this.db.selectFrom("guild_snapshots").selectAll().where("guild_id", "=", guildId).where("id", "=", id).executeTakeFirst();
    if (!row) return null;
    return {
      summary: {
        id: row.id,
        guildId: row.guild_id,
        createdAt: row.created_at,
        hash: row.hash,
        roleCount: Number(row.role_count),
        channelCount: Number(row.channel_count)
      },
      data: parseJson<T>(row.data_json, null as T),
      raw: row.data_json
    };
  }

  async prune(guildId: string, keep: number): Promise<number> {
    const keepRows = await this.db
      .selectFrom("guild_snapshots")
      .select("id")
      .where("guild_id", "=", guildId)
      .orderBy("created_at", "desc")
      .limit(keep)
      .execute();
    const keepIds = keepRows.map((row) => row.id);
    if (keepIds.length === 0) return 0;
    const result = await this.db.deleteFrom("guild_snapshots").where("guild_id", "=", guildId).where("id", "not in", keepIds).executeTakeFirst();
    return Number(result.numDeletedRows);
  }
}
