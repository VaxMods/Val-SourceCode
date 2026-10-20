import type { Kysely } from "kysely";
import { parseJson, toJson } from "../json.js";
import type { Database } from "../types.js";

export interface ProtectedRoleRecord {
  guildId: string;
  roleId: string;
  allowedGranterIds: string[];
  allowedGranterRoleIds: string[];
  createdBy: string;
  createdAt: string;
}

export class ProtectedRoleRepository {
  constructor(private readonly db: Kysely<Database>) {}

  async list(guildId: string): Promise<ProtectedRoleRecord[]> {
    const rows = await this.db.selectFrom("protected_roles").selectAll().where("guild_id", "=", guildId).execute();
    return rows.map((row) => ({
      guildId: row.guild_id,
      roleId: row.role_id,
      allowedGranterIds: parseJson<string[]>(row.allowed_granter_ids_json, []),
      allowedGranterRoleIds: parseJson<string[]>(row.allowed_granter_role_ids_json, []),
      createdBy: row.created_by,
      createdAt: row.created_at
    }));
  }

  async upsert(record: ProtectedRoleRecord): Promise<void> {
    await this.db.transaction().execute(async (trx) => {
      await trx.deleteFrom("protected_roles").where("guild_id", "=", record.guildId).where("role_id", "=", record.roleId).execute();
      await trx
        .insertInto("protected_roles")
        .values({
          guild_id: record.guildId,
          role_id: record.roleId,
          allowed_granter_ids_json: toJson(record.allowedGranterIds),
          allowed_granter_role_ids_json: toJson(record.allowedGranterRoleIds),
          created_by: record.createdBy,
          created_at: record.createdAt
        })
        .execute();
    });
  }

  async remove(guildId: string, roleId: string): Promise<boolean> {
    const result = await this.db.deleteFrom("protected_roles").where("guild_id", "=", guildId).where("role_id", "=", roleId).executeTakeFirst();
    return Number(result.numDeletedRows) > 0;
  }
}
