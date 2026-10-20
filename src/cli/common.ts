import { z } from "zod";
import type { Logger } from "pino";
import { dotenvHints, loadDotEnv, type DotEnvResult } from "../config/dotenv.js";
import { ConfigurationError, errorMessage } from "../core/errors.js";
import { createLogger } from "../core/logger.js";
import { redactString } from "../core/redact.js";
import { openDatabase, type DatabaseHandle } from "../database/connection.js";

const cliEnvSchema = z.object({
  DATABASE_DRIVER: z.enum(["sqlite", "postgres"]).default("sqlite"),
  SQLITE_PATH: z.string().min(1).default("./data/val-protection.db"),
  DATABASE_URL: z.string().optional(),
  DATABASE_POOL_SIZE: z.coerce.number().int().min(1).max(50).default(2),
  BACKUP_DIR: z.string().min(1).default("./backups"),
  BACKUP_KEEP: z.coerce.number().int().min(1).max(365).default(14),
  CONFIG_PATH: z.string().min(1).default("./config/val-protection.json"),
  EVIDENCE_HMAC_KEY: z.string().optional(),
  DISCORD_TOKEN: z.string().optional(),
  DISCORD_CLIENT_ID: z.string().regex(/^\d{17,20}$/).optional(),
  DEV_GUILD_ID: z.string().regex(/^\d{17,20}$/).optional()
});

export type CliEnv = z.infer<typeof cliEnvSchema>;

let dotenvResult: DotEnvResult | null = null;

export function envHints(): string[] {
  return dotenvResult ? dotenvHints(dotenvResult) : [];
}

export function cliEnv(): CliEnv {
  dotenvResult ??= loadDotEnv();
  const cleaned: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) if (typeof value === "string" && value.trim() !== "") cleaned[key] = value.trim();
  const parsed = cliEnvSchema.safeParse(cleaned);
  if (!parsed.success) throw new ConfigurationError("Invalid environment", [...parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`), ...envHints()]);
  if (parsed.data.DATABASE_DRIVER === "postgres" && !parsed.data.DATABASE_URL) throw new ConfigurationError("DATABASE_URL is required for postgres");
  return parsed.data;
}

export function cliLogger(): Logger {
  return createLogger({ level: "info", logDir: null }).logger;
}

export function openCliDatabase(env: CliEnv, logger: Logger): DatabaseHandle {
  return env.DATABASE_DRIVER === "postgres"
    ? openDatabase({ driver: "postgres", url: env.DATABASE_URL as string, poolSize: env.DATABASE_POOL_SIZE }, logger)
    : openDatabase({ driver: "sqlite", path: env.SQLITE_PATH }, logger);
}

export function runCli(name: string, task: (logger: Logger) => Promise<number | void>): void {
  const logger = cliLogger();
  task(logger)
    .then((code) => {
      process.exitCode = typeof code === "number" ? code : 0;
    })
    .catch((error: unknown) => {
      logger.error({ tool: name, err: redactString(errorMessage(error)) }, `${name} failed`);
      process.exitCode = 1;
    });
}
