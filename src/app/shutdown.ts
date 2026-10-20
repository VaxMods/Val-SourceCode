import type { Client } from "discord.js";
import type { Redis } from "ioredis";
import { errorMessage } from "../core/errors.js";
import type { LoggerHandle } from "../core/logger.js";
import type { DatabaseHandle } from "../database/connection.js";
import type { Scheduler } from "../jobs/scheduler.js";
import type { InFlightTracker } from "./inFlight.js";

export interface ShutdownResources {
  client: Client;
  scheduler: Scheduler;
  tracker: InFlightTracker;
  database: DatabaseHandle;
  redis: Redis | null;
  loggerHandle: LoggerHandle;
  timeoutMs: number;
}

export function installShutdown(resources: ShutdownResources): void {
  const { logger } = resources.loggerHandle;
  let stopping = false;
  const stop = async (reason: string, code: number): Promise<void> => {
    if (stopping) return;
    stopping = true;
    logger.info({ reason, inFlight: resources.tracker.size }, "Shutting down");
    const force = setTimeout(() => {
      logger.error("Graceful shutdown timed out; forcing exit");
      resources.loggerHandle.flush();
      process.exit(code === 0 ? 1 : code);
    }, resources.timeoutMs + 5000);
    force.unref();
    resources.scheduler.stop();
    const drained = await resources.tracker.drain(resources.timeoutMs);
    if (!drained) logger.warn("Some event handlers did not finish before the shutdown timeout");
    try {
      await resources.client.destroy();
    } catch (error) {
      logger.error({ err: errorMessage(error) }, "Discord client shutdown failed");
    }
    try {
      await resources.redis?.quit();
    } catch (error) {
      logger.error({ err: errorMessage(error) }, "Redis shutdown failed");
    }
    try {
      await resources.database.close();
    } catch (error) {
      logger.error({ err: errorMessage(error) }, "Database shutdown failed");
    }
    logger.info("Shutdown complete");
    resources.loggerHandle.flush();
    process.exit(code);
  };
  process.on("SIGINT", () => void stop("SIGINT", 0));
  process.on("SIGTERM", () => void stop("SIGTERM", 0));
  process.on("SIGHUP", () => {
    resources.loggerHandle.reopen();
    logger.info("Log file reopened");
  });
  process.on("uncaughtException", (error) => {
    logger.fatal({ err: errorMessage(error), stack: error.stack }, "Uncaught exception");
    void stop("uncaughtException", 1);
  });
  process.on("unhandledRejection", (reason) => {
    logger.error({ err: errorMessage(reason) }, "Unhandled promise rejection");
  });
}
