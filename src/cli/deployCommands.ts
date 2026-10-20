import { REST, Routes } from "discord.js";
import { buildSecurityCommand } from "../commands/definitions.js";
import { ConfigurationError } from "../core/errors.js";
import { cliEnv, envHints, runCli } from "./common.js";

runCli("deploy-commands", async (logger) => {
  const env = cliEnv();
  if (!env.DISCORD_TOKEN || !env.DISCORD_CLIENT_ID) throw new ConfigurationError("DISCORD_TOKEN and DISCORD_CLIENT_ID are required", envHints());
  const global = process.argv.includes("--global");
  const rest = new REST({ version: "10" }).setToken(env.DISCORD_TOKEN);
  const body = [buildSecurityCommand()];
  if (global) {
    await rest.put(Routes.applicationCommands(env.DISCORD_CLIENT_ID), { body });
    logger.info("Global /security command deployed (propagation can take up to one hour)");
    return;
  }
  if (!env.DEV_GUILD_ID) throw new ConfigurationError("DEV_GUILD_ID is required for guild deployment; use --global to deploy everywhere");
  await rest.put(Routes.applicationGuildCommands(env.DISCORD_CLIENT_ID, env.DEV_GUILD_ID), { body });
  logger.info({ guildId: env.DEV_GUILD_ID }, "Guild /security command deployed");
});
