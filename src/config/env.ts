import { z } from "zod";
import { ConfigurationError } from "../core/errors.js";

const booleanFlag = z
  .enum(["true", "false", "1", "0", "yes", "no"])
  .transform((value) => value === "true" || value === "1" || value === "yes");

const snowflake = z.string().regex(/^\d{17,20}$/, "must be a Discord snowflake");

const envSchema = z
  .object({
    NODE_ENV: z.enum(["development", "production", "test"]).default("production"),
    DISCORD_TOKEN: z.string().min(50, "DISCORD_TOKEN looks invalid").regex(/^[A-Za-z0-9._-]+$/, "DISCORD_TOKEN contains invalid characters"),
    DISCORD_CLIENT_ID: snowflake,
    DEV_GUILD_ID: snowflake.optional(),
    CONFIG_PATH: z.string().min(1).default("./config/val-protection.json"),
    DATABASE_DRIVER: z.enum(["sqlite", "postgres"]).default("sqlite"),
    SQLITE_PATH: z.string().min(1).default("./data/val-protection.db"),
    DATABASE_URL: z.string().optional(),
    DATABASE_POOL_SIZE: z.coerce.number().int().min(1).max(50).default(10),
    REDIS_URL: z.string().optional(),
    EVIDENCE_HMAC_KEY: z.string().min(1, "EVIDENCE_HMAC_KEY is required"),
    ALERT_FALLBACK_WEBHOOK_URL: z.string().optional(),
    LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
    LOG_DIR: z.string().min(1).default("./logs"),
    BACKUP_DIR: z.string().min(1).default("./backups"),
    MIGRATE_ON_START: booleanFlag.default(true),
    SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(10000)
  })
  .superRefine((value, context) => {
    if (value.DATABASE_DRIVER === "postgres" && !value.DATABASE_URL) {
      context.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "DATABASE_URL is required when DATABASE_DRIVER=postgres" });
    }
    if (value.DATABASE_URL && !/^postgres(ql)?:\/\//.test(value.DATABASE_URL)) {
      context.addIssue({ code: "custom", path: ["DATABASE_URL"], message: "DATABASE_URL must start with postgres:// or postgresql://" });
    }
    if (value.REDIS_URL && !/^rediss?:\/\//.test(value.REDIS_URL)) {
      context.addIssue({ code: "custom", path: ["REDIS_URL"], message: "REDIS_URL must start with redis:// or rediss://" });
    }
    if (
      value.ALERT_FALLBACK_WEBHOOK_URL &&
      !/^https:\/\/(?:[a-z0-9-]+\.)?discord(?:app)?\.com\/api(?:\/v\d+)?\/webhooks\/\d+\/[A-Za-z0-9_-]+$/.test(value.ALERT_FALLBACK_WEBHOOK_URL)
    ) {
      context.addIssue({ code: "custom", path: ["ALERT_FALLBACK_WEBHOOK_URL"], message: "ALERT_FALLBACK_WEBHOOK_URL must be a Discord webhook URL" });
    }
  });

export type Env = z.infer<typeof envSchema>;

export type EnvSubset = Partial<Record<keyof Env, string>>;

export function parseEnv(source: NodeJS.ProcessEnv): Env {
  const cleaned: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === "string" && value.trim() !== "") cleaned[key] = value.trim();
  }
  const result = envSchema.safeParse(cleaned);
  if (!result.success) {
    throw new ConfigurationError(
      "Invalid environment configuration",
      result.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    );
  }
  decodeHmacKey(result.data.EVIDENCE_HMAC_KEY);
  return result.data;
}

export function decodeHmacKey(raw: string): Buffer {
  const trimmed = raw.trim();
  let key: Buffer;
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    key = Buffer.from(trimmed, "hex");
  } else if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
    key = Buffer.from(trimmed.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  } else {
    throw new ConfigurationError("EVIDENCE_HMAC_KEY must be hex or base64 encoded");
  }
  if (key.length < 32) {
    throw new ConfigurationError("EVIDENCE_HMAC_KEY must decode to at least 32 bytes");
  }
  return key;
}
