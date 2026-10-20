import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { decodeHmacKey } from "../config/env.js";
import { systemClock } from "../core/clock.js";
import { ConfigurationError } from "../core/errors.js";
import { HealthMonitor } from "../core/health.js";
import { openDatabase, pendingMigrations } from "../database/connection.js";
import { createRepositories } from "../database/repositories/index.js";
import { EvidenceLog } from "../security/evidence/evidenceLog.js";
import { MemoryLockManager } from "../security/infra/lockManager.js";
import { cliEnv, envHints, runCli } from "./common.js";

runCli("restore-test", async (logger) => {
  const env = cliEnv();
  if (env.DATABASE_DRIVER !== "sqlite") {
    logger.info("For PostgreSQL, restore the latest dump into a scratch database with pg_restore --create, then run npm run verify-logs against it (see docs/DEPLOYMENT.md).");
    return 0;
  }
  if (!env.EVIDENCE_HMAC_KEY) throw new ConfigurationError("EVIDENCE_HMAC_KEY is required to validate a restored backup", envHints());
  const explicit = process.argv[2];
  const candidates = fs.existsSync(env.BACKUP_DIR)
    ? fs.readdirSync(env.BACKUP_DIR).filter((name) => name.startsWith("val-protection-") && name.endsWith(".db")).sort().reverse()
    : [];
  const source = explicit ?? (candidates[0] ? path.join(env.BACKUP_DIR, candidates[0]) : null);
  if (!source || !fs.existsSync(source)) throw new ConfigurationError("No SQLite backup found; run npm run backup first or pass a file path");
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "val-protection-restore-"));
  const copy = path.join(scratch, "restore.db");
  fs.copyFileSync(source, copy);
  const database = openDatabase({ driver: "sqlite", path: copy }, logger);
  try {
    const pending = await pendingMigrations(database.db);
    const repos = createRepositories(database.db);
    const log = new EvidenceLog(repos.events, decodeHmacKey(env.EVIDENCE_HMAC_KEY), new MemoryLockManager(), systemClock, logger, new HealthMonitor(), { mirrorPath: null, fallbackPath: null });
    let failures = 0;
    for (const guildId of await repos.events.guildIds()) {
      const result = await log.verify(guildId);
      if (!result.ok) failures += 1;
      logger.info({ guildId, ok: result.ok, records: result.checked, reason: result.reason }, "Restored evidence chain checked");
    }
    logger.info({ source, pendingMigrations: pending, failures }, failures === 0 ? "Restore test passed" : "Restore test FAILED");
    return failures === 0 ? 0 : 2;
  } finally {
    await database.close();
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
