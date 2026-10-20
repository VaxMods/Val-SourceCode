import type { Kysely } from "kysely";
import type { WhitelistScope } from "../../core/types.js";
import { parseJson, toJson } from "../json.js";
import type { Database, WhitelistTable } from "../types.js";

export interface WhitelistEntry {
  id: string;
  guildId: string;
  subjectId: string;
  subjectType: "user" | "bot";
  scopes: WhitelistScope[];
  reason: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
}

function toEntry(row: WhitelistTable): WhitelistEntry {
  return {
    id: row.id,
    guildId: row.guild_id,
    subjectId: row.subject_id,
    subjectType: row.subject_type === "bot" ? "bot" : "user",
    scopes: parseJson<WhitelistScope[]>(row.scopes_json, []),
    reason: row.reason,
    createdBy: row.created_by,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  };
}

export class WhitelistRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async listActive(guildId: string, nowIso: string): Promise<WhitelistEntry[]> {
    const rows = await this.db
      .selectFrom("whitelist_entries")
      .selectAll()
      .where("guild_id", "=", guildId)
      .where("revoked_at", "is", null)
      .where((eb) => eb.or([eb("expires_at", "is", null), eb("expires_at", ">", nowIso)]))
      .orderBy("created_at", "asc")
      .execute();
    return rows.map(toEntry);
  }

  async add(entry: WhitelistEntry): Promise<void> {
    await this.db
      .insertInto("whitelist_entries")
      .values({
        id: entry.id,
        guild_id: entry.guildId,
        subject_id: entry.subjectId,
        subject_type: entry.subjectType,
        scopes_json: toJson(entry.scopes),
        reason: entry.reason,
        created_by: entry.createdBy,
        created_at: entry.createdAt,
        expires_at: entry.expiresAt,
        revoked_at: null,
        revoked_by: null
      })
      .execute();
  }

  async revokeSubject(guildId: string, subjectId: string, revokedBy: string, atIso: string): Promise<number> {
    const result = await this.db
      .updateTable("whitelist_entries")
      .set({ revoked_at: atIso, revoked_by: revokedBy })
      .where("guild_id", "=", guildId)
      .where("subject_id", "=", subjectId)
      .where("revoked_at", "is", null)
      .executeTakeFirst();
    return Number(result.numUpdatedRows);
  }
}
