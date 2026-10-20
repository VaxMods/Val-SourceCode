import fs from "node:fs";
import path from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { Kysely, PostgresDialect, SqliteDialect, sql } from "kysely";
import { Migrator, type MigrationResultSet } from "kysely/migration";
import pg from "pg";
import type { Logger } from "pino";
import { PersistenceError, errorMessage } from "../core/errors.js";
import { StaticMigrationProvider } from "./migrations.js";
import type { Database } from "./types.js";

export type DatabaseOptions =
  | { driver: "sqlite"; path: string }
  | { driver: "postgres"; url: string; poolSize: number };

export interface DatabaseHandle {
  db: Kysely<Database>;
  driver: "sqlite" | "postgres";
  sqlite: BetterSqlite3.Database | null;
  close(): Promise<void>;
}

export function openDatabase(options: DatabaseOptions, logger?: Logger): DatabaseHandle {
  if (options.driver === "sqlite") {
    const inMemory = options.path === ":memory:";
    if (!inMemory) fs.mkdirSync(path.dirname(path.resolve(options.path)), { recursive: true, mode: 0o700 });
    const sqlite = new BetterSqlite3(options.path);
    sqlite.pragma("journal_mode = WAL");
    sqlite.pragma("foreign_keys = ON");
    sqlite.pragma("busy_timeout = 5000");
    sqlite.pragma("synchronous = NORMAL");
    if (!inMemory && process.platform !== "win32") {
      try {
        fs.chmodSync(options.path, 0o600);
      } catch (error) {
        logger?.warn({ err: errorMessage(error) }, "Could not restrict SQLite file permissions");
      }
    }
    const db = new Kysely<Database>({ dialect: new SqliteDialect({ database: sqlite }) });
    return { db, driver: "sqlite", sqlite, close: () => db.destroy() };
  }
  const pool = new pg.Pool({
    connectionString: options.url,
    max: options.poolSize,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000
  });
  pool.on("error", (error) => logger?.error({ err: errorMessage(error) }, "PostgreSQL pool error"));
  const db = new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
  return { db, driver: "postgres", sqlite: null, close: () => db.destroy() };
}

export async function migrateToLatest(db: Kysely<Database>, logger?: Logger): Promise<MigrationResultSet> {
  const migrator = new Migrator({ db, provider: new StaticMigrationProvider() });
  const result = await migrator.migrateToLatest();
  for (const item of result.results ?? []) {
    logger?.info({ migration: item.migrationName, status: item.status }, "Database migration");
  }
  if (result.error) throw new PersistenceError(`Database migration failed: ${errorMessage(result.error)}`, { cause: result.error });
  return result;
}

export async function pendingMigrations(db: Kysely<Database>): Promise<string[]> {
  const migrator = new Migrator({ db, provider: new StaticMigrationProvider() });
  const list = await migrator.getMigrations();
  return list.filter((item) => !item.executedAt).map((item) => item.name);
}

export async function pingDatabase(db: Kysely<Database>): Promise<boolean> {
  try {
    await sql`select 1`.execute(db);
    return true;
  } catch {
    return false;
  }
}
