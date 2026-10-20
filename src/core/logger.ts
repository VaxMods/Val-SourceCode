import fs from "node:fs";
import path from "node:path";
import { pino, type Logger, type LevelWithSilent, type StreamEntry } from "pino";
import { REDACTED, redactSecrets, redactString } from "./redact.js";

export type AppLogger = Logger;

export interface LoggerHandle {
  logger: Logger;
  ready: Promise<void>;
  reopen(): void;
  flush(): void;
}

const REDACT_PATHS = [
  "token",
  "*.token",
  "*.*.token",
  "password",
  "*.password",
  "secret",
  "*.secret",
  "authorization",
  "*.authorization",
  "headers.authorization",
  "webhookUrl",
  "*.webhookUrl",
  "url",
  "*.url"
];

export function createLogger(options: { level: LevelWithSilent; logDir: string | null }): LoggerHandle {
  const streams: StreamEntry[] = [{ level: options.level === "silent" ? "fatal" : options.level, stream: process.stdout }];
  let fileStream: ReturnType<typeof pino.destination> | null = null;
  let ready: Promise<void> = Promise.resolve();
  if (options.logDir) {
    fs.mkdirSync(options.logDir, { recursive: true, mode: 0o700 });
    const stream = pino.destination({ dest: path.join(options.logDir, "val-protection.log"), mkdir: true, sync: false, mode: 0o600 });
    ready = new Promise((resolve) => stream.once("ready", () => resolve()));
    fileStream = stream;
    streams.push({ level: options.level === "silent" ? "fatal" : options.level, stream });
  }
  const logger = pino(
    {
      level: options.level,
      base: { service: "val-protection" },
      timestamp: pino.stdTimeFunctions.isoTime,
      redact: { paths: REDACT_PATHS, censor: REDACTED },
      formatters: {
        level: (label) => ({ level: label }),
        log: (object) => redactSecrets(object)
      },
      hooks: {
        logMethod(args, method) {
          const sanitized = args.map((item) => (typeof item === "string" ? redactString(item) : item)) as Parameters<typeof method>;
          method.apply(this, sanitized);
        }
      }
    },
    pino.multistream(streams)
  );
  return {
    logger,
    ready,
    reopen: () => fileStream?.reopen(),
    flush: () => {
      try {
        fileStream?.flushSync();
      } catch {
        return;
      }
    }
  };
}

export function createSilentLogger(): Logger {
  return pino({ level: "silent" });
}
