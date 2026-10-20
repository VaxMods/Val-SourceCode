import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import BetterSqlite3 from "better-sqlite3";
import { cliEnv, runCli } from "./common.js";

function stamp(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\..+$/, "");
}

function prune(directory: string, keep: number, extension: string): string[] {
  const files = fs
    .readdirSync(directory)
    .filter((name) => name.startsWith("val-protection-") && name.endsWith(extension))
    .sort()
    .reverse();
  const removed = files.slice(keep);
  for (const name of removed) fs.unlinkSync(path.join(directory, name));
  return removed;
}

runCli("backup", async (logger) => {
  const env = cliEnv();
  fs.mkdirSync(env.BACKUP_DIR, { recursive: true, mode: 0o700 });
  if (env.DATABASE_DRIVER === "sqlite") {
    const target = path.join(env.BACKUP_DIR, `val-protection-${stamp()}.db`);
    const source = new BetterSqlite3(env.SQLITE_PATH, { readonly: true, fileMustExist: true });
    try {
      await source.backup(target);
    } finally {
      source.close();
    }
    if (process.platform !== "win32") fs.chmodSync(target, 0o600);
    const removed = prune(env.BACKUP_DIR, env.BACKUP_KEEP, ".db");
    logger.info({ target, sizeBytes: fs.statSync(target).size, pruned: removed.length }, "SQLite backup created");
    return;
  }
  const url = new URL(env.DATABASE_URL as string);
  const target = path.join(env.BACKUP_DIR, `val-protection-${stamp()}.dump`);
  const child = spawn("pg_dump", ["--format=custom", "--no-owner", `--file=${target}`], {
    env: {
      ...process.env,
      PGHOST: url.hostname,
      PGPORT: url.port || "5432",
      PGUSER: decodeURIComponent(url.username),
      PGPASSWORD: decodeURIComponent(url.password),
      PGDATABASE: url.pathname.replace(/^\//, ""),
      PGSSLMODE: url.searchParams.get("sslmode") ?? process.env.PGSSLMODE ?? "prefer"
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  const code: number = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (exit) => resolve(exit ?? 1));
  });
  if (code !== 0) throw new Error(`pg_dump exited with code ${code}: ${stderr.trim().slice(0, 500)}`);
  if (process.platform !== "win32") fs.chmodSync(target, 0o600);
  const removed = prune(env.BACKUP_DIR, env.BACKUP_KEEP, ".dump");
  logger.info({ target, sizeBytes: fs.statSync(target).size, pruned: removed.length }, "PostgreSQL backup created");
});
