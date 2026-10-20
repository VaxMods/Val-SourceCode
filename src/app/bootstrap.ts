import path from "node:path";
import { Events, type Client } from "discord.js";
import { Redis } from "ioredis";
import type { Logger } from "pino";
import { CommandRouter } from "../commands/router.js";
import { ConfirmationService } from "../commands/confirmations.js";
import { dotenvHints, loadDotEnv, type DotEnvResult } from "../config/dotenv.js";
import { decodeHmacKey, parseEnv, type Env } from "../config/env.js";
import { loadConfigFile } from "../config/loader.js";
import { systemClock } from "../core/clock.js";
import { ConfigurationError, errorMessage } from "../core/errors.js";
import { HealthMonitor } from "../core/health.js";
import { createLogger, type LoggerHandle } from "../core/logger.js";
import { migrateToLatest, openDatabase, pendingMigrations, type DatabaseHandle } from "../database/connection.js";
import { createRepositories } from "../database/repositories/index.js";
import { createDiscordClient } from "../discord/client.js";
import { DiscordJsGateway } from "../discord/discordGateway.js";
import { registerEventHandlers } from "../discord/events.js";
import { Scheduler } from "../jobs/scheduler.js";
import { MemoryCounterStore, RedisCounterStore, type CounterStore } from "../security/infra/counterStore.js";
import { MemoryLockManager, RedisLockManager, type LockManager } from "../security/infra/lockManager.js";
import { createKernel } from "../security/kernel.js";
import { InFlightTracker } from "./inFlight.js";
import { installShutdown } from "./shutdown.js";
import { VERSION, verifyGuild } from "./startup.js";

export async function openConfiguredDatabase(env: Env, logger: Logger): Promise<DatabaseHandle> {
  const database =
    env.DATABASE_DRIVER === "postgres"
      ? openDatabase({ driver: "postgres", url: env.DATABASE_URL as string, poolSize: env.DATABASE_POOL_SIZE }, logger)
      : openDatabase({ driver: "sqlite", path: env.SQLITE_PATH }, logger);
  if (env.MIGRATE_ON_START) {
    await migrateToLatest(database.db, logger);
  } else {
    const pending = await pendingMigrations(database.db);
    if (pending.length > 0) throw new Error(`Pending database migrations: ${pending.join(", ")}. Run npm run migrate.`);
  }
  return database;
}

async function connectRedis(url: string, logger: Logger): Promise<Redis> {
  const redis = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 2, enableOfflineQueue: false, connectTimeout: 5000 });
  redis.on("error", (error) => logger.error({ err: errorMessage(error) }, "Redis error"));
  await redis.connect();
  await redis.ping();
  return redis;
}

export async function main(): Promise<void> {
  const dotenv = loadDotEnv();
  let env: Env;
  try {
    env = parseEnv(process.env);
  } catch (error) {
    if (error instanceof ConfigurationError) throw new ConfigurationError("Invalid environment configuration", [...error.issues, ...dotenvHints(dotenv)]);
    throw error;
  }
  const loggerHandle: LoggerHandle = createLogger({ level: env.LOG_LEVEL, logDir: env.LOG_DIR });
  await loggerHandle.ready;
  const logger = loggerHandle.logger;
  try {
    await start(env, loggerHandle, dotenv);
  } catch (error) {
    logger.fatal({ err: errorMessage(error) }, "Startup failed");
    loggerHandle.flush();
    throw error;
  }
}

async function start(env: Env, loggerHandle: LoggerHandle, dotenv: DotEnvResult): Promise<void> {
  const logger = loggerHandle.logger;
  logger.info({ version: VERSION, node: process.version }, "Val Protection starting");
  if (dotenv.file) {
    logger.info({ file: dotenv.file, variables: dotenv.loaded.length }, "Environment file loaded");
    for (const hint of dotenvHints(dotenv)) logger.warn({ hint }, "Environment file warning");
  }
  const config = loadConfigFile(env.CONFIG_PATH, { optional: true });
  if (!config.fileFound) logger.info({ path: env.CONFIG_PATH }, "No configuration file: built-in defaults apply; configure each server with /security panel");
  for (const warning of config.warnings) logger.warn({ warning }, "Configuration warning");
  const hmacKey = decodeHmacKey(env.EVIDENCE_HMAC_KEY);
  const database = await openConfiguredDatabase(env, logger);
  let redis: Redis | null = null;
  let counters: CounterStore = new MemoryCounterStore();
  let locks: LockManager = new MemoryLockManager();
  if (env.REDIS_URL) {
    redis = await connectRedis(env.REDIS_URL, logger);
    counters = new RedisCounterStore(redis);
    locks = new RedisLockManager(redis);
    logger.info("Redis counters and locks enabled");
  }
  const health = new HealthMonitor();
  const client = createDiscordClient();
  const gateway = new DiscordJsGateway(client as Client<true>, logger.child({ module: "gateway" }));
  const kernel = createKernel({
    gateway,
    config,
    repos: createRepositories(database.db),
    counters,
    locks,
    clock: systemClock,
    logger,
    health,
    hmacKey,
    files: {
      evidenceMirror: path.join(env.LOG_DIR, "evidence.jsonl"),
      evidenceFallback: path.join(env.LOG_DIR, "evidence-fallback.jsonl"),
      alertFallback: path.join(env.LOG_DIR, "alerts-fallback.jsonl")
    },
    fallbackWebhookUrl: env.ALERT_FALLBACK_WEBHOOK_URL ?? null
  });
  await kernel.lockdown.initialize();
  const confirmations = new ConfirmationService(systemClock);
  const integrity = new Map<string, { ok: boolean; checked: number; at: number; reason: string | null }>();
  const router = new CommandRouter({
    kernel,
    confirmations,
    logger: logger.child({ module: "commands" }),
    databaseDriver: database.driver,
    redisEnabled: redis !== null,
    backupDir: env.BACKUP_DIR,
    startedAt: Date.now(),
    integrity
  });
  const tracker = new InFlightTracker();
  const guildIds = () => [...client.guilds.cache.keys()];
  const scheduler = new Scheduler({ kernel, confirmations, guildIds, integrity, logger: logger.child({ module: "scheduler" }) });
  registerEventHandlers({
    client,
    kernel,
    router,
    tracker,
    health,
    logger: logger.child({ module: "events" }),
    onGuildAvailable: (guildId) => verifyGuild(kernel, guildId, config.warnings, logger)
  });
  client.once(Events.ClientReady, (ready) => {
    logger.info({ user: ready.user.tag, guilds: ready.guilds.cache.size }, "Connected to Discord");
    void (async () => {
      for (const guildId of guildIds()) {
        if (!kernel.policies.isGuildAllowed(guildId)) {
          logger.warn({ guildId }, "Guild not in allowedGuildIds; ignored");
          continue;
        }
        try {
          await verifyGuild(kernel, guildId, config.warnings, logger);
        } catch (error) {
          logger.error({ err: errorMessage(error), guildId }, "Startup verification failed");
        }
      }
      await kernel.snapshots.captureDue(guildIds().filter((id) => kernel.policies.isGuildAllowed(id)));
      scheduler.start();
    })();
  });
  installShutdown({ client, scheduler, tracker, database, redis, loggerHandle, timeoutMs: env.SHUTDOWN_TIMEOUT_MS });
  await client.login(env.DISCORD_TOKEN);
}
