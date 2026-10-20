import type { Kysely } from "kysely";
import { parseJson, toJson } from "../json.js";
import type { Database } from "../types.js";

export interface GuildSettingsRecord {
  guildId: string;
  overrides: Record<string, unknown>;
  revision: number;
  updatedAt: string;
  updatedBy: string;
}

export class SettingsRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async get(guildId: string): Promise<GuildSettingsRecord | null> {
    const row = await this.db.selectFrom("guild_settings").selectAll().where("guild_id", "=", guildId).executeTakeFirst();
    if (!row) return null;
    return {
      guildId: row.guild_id,
      overrides: parseJson<Record<string, unknown>>(row.overrides_json, {}),
      revision: row.revision,
      updatedAt: row.updated_at,
      updatedBy: row.updated_by
    };
  }

  async save(guildId: string, overrides: Record<string, unknown>, expectedRevision: number, updatedBy: string, at: string): Promise<boolean> {
    if (expectedRevision === 0) {
      const existing = await this.get(guildId);
      if (existing) return false;
      await this.db
        .insertInto("guild_settings")
        .values({ guild_id: guildId, overrides_json: toJson(overrides), revision: 1, updated_at: at, updated_by: updatedBy })
        .execute();
      return true;
    }
    const result = await this.db
      .updateTable("guild_settings")
      .set({ overrides_json: toJson(overrides), revision: expectedRevision + 1, updated_at: at, updated_by: updatedBy })
      .where("guild_id", "=", guildId)
      .where("revision", "=", expectedRevision)
      .executeTakeFirst();
    return Number(result.numUpdatedRows) === 1;
  }
}
