import fs from "node:fs";
import path from "node:path";
import { parseEnv } from "node:util";

export interface DotEnvResult {
  file: string | null;
  loaded: string[];
  ignored: string[];
  invalidLines: number[];
}

const KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const EDGE_SPACES = /^[\s​‌‍⁠﻿]+|[\s​‌‍⁠﻿]+$/g;

export function decodeEnvFile(buffer: Buffer): string {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString("utf16le");
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    swapped.swap16();
    return swapped.toString("utf16le");
  }
  const text = buffer.toString("utf8");
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function normalizeEnvText(text: string): { content: string; invalidLines: number[] } {
  const invalidLines: number[] = [];
  const lines = text.split(/\r\n|\r|\n/).map((line, index) => {
    const trimmed = line.replace(EDGE_SPACES, "");
    if (trimmed === "" || trimmed.startsWith("#")) return trimmed;
    const separator = trimmed.indexOf("=");
    if (separator <= 0) {
      invalidLines.push(index + 1);
      return "";
    }
    const key = trimmed
      .slice(0, separator)
      .replace(/^export\s+/, "")
      .replace(/[^A-Za-z0-9_]/g, "");
    if (!KEY_PATTERN.test(key)) {
      invalidLines.push(index + 1);
      return "";
    }
    return `${key}=${trimmed.slice(separator + 1).replace(EDGE_SPACES, "")}`;
  });
  return { content: lines.join("\n"), invalidLines };
}

export function loadDotEnv(file = process.env.ENV_FILE ?? ".env", target: NodeJS.ProcessEnv = process.env): DotEnvResult {
  const resolved = path.resolve(file);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) return { file: null, loaded: [], ignored: [], invalidLines: [] };
  const { content, invalidLines } = normalizeEnvText(decodeEnvFile(fs.readFileSync(resolved)));
  const parsed = parseEnv(content) as Record<string, string>;
  const loaded: string[] = [];
  const ignored: string[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    const existing = target[key];
    if (existing !== undefined && existing.trim() !== "") {
      ignored.push(key);
      continue;
    }
    target[key] = value;
    loaded.push(key);
  }
  return { file: resolved, loaded, ignored, invalidLines };
}

export function dotenvHints(result: DotEnvResult): string[] {
  const hints: string[] = [];
  if (!result.file) hints.push(`No .env file found at ${path.resolve(process.env.ENV_FILE ?? ".env")}; run the command from the project folder or set ENV_FILE`);
  if (result.invalidLines.length > 0) hints.push(`.env lines ignored because they are not KEY=value: ${result.invalidLines.join(", ")}`);
  if (result.ignored.length > 0) hints.push(`Already defined in the system environment, so the system value wins: ${result.ignored.join(", ")}`);
  return hints;
}
