import type { Kysely } from "kysely";
import type { Migration, MigrationProvider } from "kysely/migration";

type AnyDb = Kysely<Record<string, never>>;

const initial: Migration = {
  async up(db: AnyDb) {
    await db.schema
      .createTable("guild_settings")
      .addColumn("guild_id", "text", (column) => column.primaryKey())
      .addColumn("overrides_json", "text", (column) => column.notNull())
      .addColumn("revision", "integer", (column) => column.notNull())
      .addColumn("updated_at", "text", (column) => column.notNull())
      .addColumn("updated_by", "text", (column) => column.notNull())
      .execute();

    await db.schema
      .createTable("whitelist_entries")
      .addColumn("id", "text", (column) => column.primaryKey())
      .addColumn("guild_id", "text", (column) => column.notNull())
      .addColumn("subject_id", "text", (column) => column.notNull())
      .addColumn("subject_type", "text", (column) => column.notNull())
      .addColumn("scopes_json", "text", (column) => column.notNull())
      .addColumn("reason", "text", (column) => column.notNull())
      .addColumn("created_by", "text", (column) => column.notNull())
      .addColumn("created_at", "text", (column) => column.notNull())
      .addColumn("expires_at", "text")
      .addColumn("revoked_at", "text")
      .addColumn("revoked_by", "text")
      .execute();
    await db.schema.createIndex("idx_whitelist_guild_subject").on("whitelist_entries").columns(["guild_id", "subject_id"]).execute();

    await db.schema
      .createTable("protected_roles")
      .addColumn("guild_id", "text", (column) => column.notNull())
      .addColumn("role_id", "text", (column) => column.notNull())
      .addColumn("allowed_granter_ids_json", "text", (column) => column.notNull())
      .addColumn("allowed_granter_role_ids_json", "text", (column) => column.notNull())
      .addColumn("created_by", "text", (column) => column.notNull())
      .addColumn("created_at", "text", (column) => column.notNull())
      .addPrimaryKeyConstraint("pk_protected_roles", ["guild_id", "role_id"])
      .execute();

    await db.schema
      .createTable("incidents")
      .addColumn("id", "text", (column) => column.primaryKey())
      .addColumn("guild_id", "text", (column) => column.notNull())
      .addColumn("type", "text", (column) => column.notNull())
      .addColumn("severity", "text", (column) => column.notNull())
      .addColumn("status", "text", (column) => column.notNull())
      .addColumn("actor_id", "text")
      .addColumn("target_id", "text")
      .addColumn("confidence", "text", (column) => column.notNull())
      .addColumn("summary", "text", (column) => column.notNull())
      .addColumn("details_json", "text", (column) => column.notNull())
      .addColumn("created_at", "text", (column) => column.notNull())
      .addColumn("updated_at", "text", (column) => column.notNull())
      .execute();
    await db.schema.createIndex("idx_incidents_guild_created").on("incidents").columns(["guild_id", "created_at"]).execute();

    await db.schema
      .createTable("security_events")
      .addColumn("guild_id", "text", (column) => column.notNull())
      .addColumn("seq", "integer", (column) => column.notNull())
      .addColumn("occurred_at", "text", (column) => column.notNull())
      .addColumn("event_type", "text", (column) => column.notNull())
      .addColumn("severity", "text", (column) => column.notNull())
      .addColumn("actor_id", "text")
      .addColumn("target_id", "text")
      .addColumn("confidence", "text", (column) => column.notNull())
      .addColumn("action", "text")
      .addColumn("action_result", "text")
      .addColumn("evidence_json", "text", (column) => column.notNull())
      .addColumn("error", "text")
      .addColumn("incident_id", "text")
      .addColumn("prev_hash", "text", (column) => column.notNull())
      .addColumn("hash", "text", (column) => column.notNull())
      .addPrimaryKeyConstraint("pk_security_events", ["guild_id", "seq"])
      .execute();
    await db.schema.createIndex("idx_events_guild_time").on("security_events").columns(["guild_id", "occurred_at"]).execute();
    await db.schema.createIndex("idx_events_incident").on("security_events").columns(["incident_id"]).execute();

    await db.schema
      .createTable("log_anchors")
      .addColumn("guild_id", "text", (column) => column.primaryKey())
      .addColumn("seq", "integer", (column) => column.notNull())
      .addColumn("hash", "text", (column) => column.notNull())
      .addColumn("purged_at", "text", (column) => column.notNull())
      .addColumn("purged_count", "integer", (column) => column.notNull())
      .execute();

    await db.schema
      .createTable("lockdowns")
      .addColumn("guild_id", "text", (column) => column.primaryKey())
      .addColumn("active", "integer", (column) => column.notNull())
      .addColumn("reason", "text", (column) => column.notNull())
      .addColumn("triggered_by", "text", (column) => column.notNull())
      .addColumn("started_at", "text", (column) => column.notNull())
      .addColumn("expires_at", "text", (column) => column.notNull())
      .addColumn("ended_at", "text")
      .addColumn("ended_by", "text")
      .addColumn("previous_state_json", "text", (column) => column.notNull())
      .execute();

    await db.schema
      .createTable("bot_registry")
      .addColumn("guild_id", "text", (column) => column.notNull())
      .addColumn("bot_id", "text", (column) => column.notNull())
      .addColumn("status", "text", (column) => column.notNull())
      .addColumn("added_by", "text")
      .addColumn("added_at", "text", (column) => column.notNull())
      .addColumn("reviewed_by", "text")
      .addColumn("reviewed_at", "text")
      .addColumn("risk_json", "text", (column) => column.notNull())
      .addPrimaryKeyConstraint("pk_bot_registry", ["guild_id", "bot_id"])
      .execute();

    await db.schema
      .createTable("guild_snapshots")
      .addColumn("id", "text", (column) => column.primaryKey())
      .addColumn("guild_id", "text", (column) => column.notNull())
      .addColumn("created_at", "text", (column) => column.notNull())
      .addColumn("data_json", "text", (column) => column.notNull())
      .addColumn("hash", "text", (column) => column.notNull())
      .addColumn("role_count", "integer", (column) => column.notNull())
      .addColumn("channel_count", "integer", (column) => column.notNull())
      .execute();
    await db.schema.createIndex("idx_snapshots_guild_created").on("guild_snapshots").columns(["guild_id", "created_at"]).execute();
  },
  async down(db: AnyDb) {
    for (const table of [
      "guild_snapshots",
      "bot_registry",
      "lockdowns",
      "log_anchors",
      "security_events",
      "incidents",
      "protected_roles",
      "whitelist_entries",
      "guild_settings"
    ]) {
      await db.schema.dropTable(table).ifExists().execute();
    }
  }
};

export const MIGRATIONS: Record<string, Migration> = {
  "2026_10_01_001_initial": initial
};

export class StaticMigrationProvider implements MigrationProvider {
  async getMigrations(): Promise<Record<string, Migration>> {
    return MIGRATIONS;
  }
}
