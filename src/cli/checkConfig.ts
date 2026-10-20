import { loadConfigFile } from "../config/loader.js";
import { ConfigurationError } from "../core/errors.js";
import { cliEnv, runCli } from "./common.js";

runCli("check-config", async (logger) => {
  const env = cliEnv();
  try {
    const config = loadConfigFile(env.CONFIG_PATH, { optional: true });
    if (!config.fileFound) {
      logger.info({ path: env.CONFIG_PATH }, "No configuration file: built-in defaults apply; configure each server with /security panel");
      return 0;
    }
    for (const warning of config.warnings) logger.warn({ warning }, "Configuration warning");
    logger.info({ path: env.CONFIG_PATH, hash: config.hash, guilds: Object.keys(config.guilds).length, warnings: config.warnings.length }, "Configuration is valid");
    return 0;
  } catch (error) {
    if (error instanceof ConfigurationError) {
      for (const issue of error.issues.length > 0 ? error.issues : [error.message]) logger.error({ issue }, "Configuration error");
      return 1;
    }
    throw error;
  }
});
