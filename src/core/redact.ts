const SENSITIVE_KEYS = new Set([
  "token",
  "password",
  "secret",
  "authorization",
  "webhookurl",
  "webhook_url",
  "url",
  "apikey",
  "api_key",
  "hmackey",
  "databaseurl",
  "redisurl",
  "connectionstring"
]);

const WEBHOOK_URL = /(https?:\/\/(?:[a-z0-9-]+\.)?discord(?:app)?\.com\/api(?:\/v\d+)?\/webhooks\/\d+\/)[A-Za-z0-9_-]+/gi;
const BOT_TOKEN = /\b[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}\b/g;
const BEARER = /\b(Bearer|Bot)\s+[A-Za-z0-9._~+/-]{16,}=*/g;
const CONNECTION_STRING = /\b(postgres(?:ql)?|redis|rediss):\/\/[^\s@/]+@/gi;

export const REDACTED = "[REDACTED]";

export function redactString(value: string): string {
  return value
    .replace(WEBHOOK_URL, `$1${REDACTED}`)
    .replace(BOT_TOKEN, REDACTED)
    .replace(BEARER, `$1 ${REDACTED}`)
    .replace(CONNECTION_STRING, `$1://${REDACTED}@`);
}

export function redactSecrets<T>(value: T, depth = 0): T {
  if (depth > 12) return value;
  if (typeof value === "string") return redactString(value) as T;
  if (typeof value === "bigint") return value.toString() as T;
  if (Array.isArray(value)) return value.map((item) => redactSecrets(item, depth + 1)) as T;
  if (value instanceof Error) {
    return { name: value.name, message: redactString(value.message) } as T;
  }
  if (value !== null && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      output[key] = SENSITIVE_KEYS.has(key.toLowerCase()) ? REDACTED : redactSecrets(item, depth + 1);
    }
    return output as T;
  }
  return value;
}

export function maskId(value: string | null | undefined): string {
  if (!value) return "unknown";
  return value;
}
