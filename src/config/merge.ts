export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function deepMerge(...sources: Array<Record<string, unknown> | undefined>): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const source of sources) {
    if (!source) continue;
    for (const [key, value] of Object.entries(source)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      const existing = output[key];
      if (isPlainObject(existing) && isPlainObject(value)) {
        output[key] = deepMerge(existing, value);
      } else if (isPlainObject(value)) {
        output[key] = deepMerge(value);
      } else if (Array.isArray(value)) {
        output[key] = [...value];
      } else {
        output[key] = value;
      }
    }
  }
  return output;
}

export function getPath(source: Record<string, unknown>, path: string): unknown {
  let current: unknown = source;
  for (const part of path.split(".")) {
    if (!isPlainObject(current)) return undefined;
    current = current[part];
  }
  return current;
}

export function setPath(source: Record<string, unknown>, path: string, value: unknown): Record<string, unknown> {
  const parts = path.split(".");
  if (parts.some((part) => FORBIDDEN_KEYS.has(part))) throw new Error("Forbidden configuration path");
  const output = deepMerge(source);
  let current: Record<string, unknown> = output;
  for (let index = 0; index < parts.length - 1; index += 1) {
    const part = parts[index] as string;
    const next = current[part];
    if (!isPlainObject(next)) current[part] = {};
    current = current[part] as Record<string, unknown>;
  }
  current[parts[parts.length - 1] as string] = value;
  return output;
}
