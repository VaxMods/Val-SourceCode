import { migrateToLatest } from "../database/connection.js";
import { cliEnv, openCliDatabase, runCli } from "./common.js";

runCli("migrate", async (logger) => {
  const env = cliEnv();
  const database = openCliDatabase(env, logger);
  try {
    const result = await migrateToLatest(database.db, logger);
    logger.info({ applied: result.results?.filter((item) => item.status === "Success").length ?? 0 }, "Database is up to date");
  } finally {
    await database.close();
  }
});
