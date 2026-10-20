import { decodeHmacKey } from "../config/env.js";
import { systemClock } from "../core/clock.js";
import { ConfigurationError } from "../core/errors.js";
import { HealthMonitor } from "../core/health.js";
import { createRepositories } from "../database/repositories/index.js";
import { EvidenceLog } from "../security/evidence/evidenceLog.js";
import { MemoryLockManager } from "../security/infra/lockManager.js";
import { cliEnv, envHints, openCliDatabase, runCli } from "./common.js";

runCli("verify-logs", async (logger) => {
  const env = cliEnv();
  if (!env.EVIDENCE_HMAC_KEY) throw new ConfigurationError("EVIDENCE_HMAC_KEY is required to verify the evidence chain", envHints());
  const database = openCliDatabase(env, logger);
  try {
    const repos = createRepositories(database.db);
    const log = new EvidenceLog(repos.events, decodeHmacKey(env.EVIDENCE_HMAC_KEY), new MemoryLockManager(), systemClock, logger, new HealthMonitor(), { mirrorPath: null, fallbackPath: null });
    let broken = 0;
    for (const guildId of await repos.events.guildIds()) {
      const result = await log.verify(guildId);
      if (result.ok) logger.info({ guildId, records: result.checked, firstSeq: result.firstSeq, lastSeq: result.lastSeq }, "Evidence chain intact");
      else {
        broken += 1;
        logger.error({ guildId, brokenAtSeq: result.brokenAtSeq, reason: result.reason }, "Evidence chain BROKEN");
      }
    }
    return broken > 0 ? 2 : 0;
  } finally {
    await database.close();
  }
});
