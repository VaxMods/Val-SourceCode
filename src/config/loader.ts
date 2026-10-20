import crypto from "node:crypto";
import fs from "node:fs";
import { ConfigurationError } from "../core/errors.js";
import { deepMerge } from "./merge.js";
import { configFileSchema, guildPolicySchema, type ConfigFile, type GlobalSettings, type GuildPolicy } from "./schema.js";
import { validatePolicySemantics } from "./validation.js";

export interface LoadedConfig {
  path: string;
  hash: string;
  fileFound: boolean;
  global: GlobalSettings;
  defaults: Record<string, unknown>;
  guilds: Record<string, Record<string, unknown>>;
  warnings: string[];
}

export function parseConfigObject(input: unknown, origin = "config"): Omit<LoadedConfig, "path" | "hash" | "fileFound"> {
  const envelope = configFileSchema.safeParse(input);
  if (!envelope.success) {
    throw new ConfigurationError(
      `Invalid ${origin}`,
      envelope.error.issues.map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
    );
  }
  const file: ConfigFile = envelope.data;
  const errors: string[] = [];
  const warnings: string[] = [];
  const scopes: Array<[string, Record<string, unknown>]> = [["defaults", {}]];
  for (const [guildId, overrides] of Object.entries(file.guilds)) scopes.push([`guilds.${guildId}`, overrides]);
  for (const [label, overrides] of scopes) {
    const merged = deepMerge(file.defaults, overrides);
    const parsed = guildPolicySchema.safeParse(merged);
    if (!parsed.success) {
      for (const issue of parsed.error.issues) errors.push(`${label}.${issue.path.join(".")}: ${issue.message}`);
      continue;
    }
    const semantic = validatePolicySemantics(parsed.data);
    for (const error of semantic.errors) errors.push(`${label}: ${error}`);
    for (const warning of semantic.warnings) warnings.push(`${label}: ${warning}`);
  }
  if (errors.length > 0) throw new ConfigurationError(`Invalid ${origin}`, errors);
  return { global: file.global, defaults: file.defaults, guilds: file.guilds, warnings };
}

export function loadConfigFile(path: string, options: { optional?: boolean } = {}): LoadedConfig {
  if (!fs.existsSync(path)) {
    if (options.optional) {
      const parsed = parseConfigObject({ version: 1 }, "default configuration");
      return { path, hash: crypto.createHash("sha256").update("defaults").digest("hex"), ...parsed, warnings: [], fileFound: false };
    }
    throw new ConfigurationError(`Configuration file not found: ${path}. Copy config/val-protection.example.json to ${path}.`);
  }
  const content = fs.readFileSync(path, "utf8");
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch (error) {
    throw new ConfigurationError(`Configuration file is not valid JSON: ${(error as Error).message}`);
  }
  const parsed = parseConfigObject(json, `configuration file ${path}`);
  const warnings = [...parsed.warnings];
  if (process.platform !== "win32") {
    const mode = fs.statSync(path).mode;
    if ((mode & 0o002) !== 0) {
      throw new ConfigurationError(`Configuration file ${path} is world-writable; run chmod 640 on it`);
    }
    if ((mode & 0o020) !== 0) warnings.push(`Configuration file ${path} is group-writable`);
  }
  return {
    path,
    hash: crypto.createHash("sha256").update(content).digest("hex"),
    ...parsed,
    warnings,
    fileFound: true
  };
}

export function resolveGuildPolicy(
  config: Pick<LoadedConfig, "defaults" | "guilds">,
  guildId: string,
  runtimeOverrides: Record<string, unknown> = {}
): GuildPolicy {
  const merged = deepMerge(config.defaults, config.guilds[guildId], runtimeOverrides);
  const parsed = guildPolicySchema.safeParse(merged);
  if (parsed.success && validatePolicySemantics(parsed.data).errors.length === 0) return parsed.data;
  return guildPolicySchema.parse(deepMerge(config.defaults, config.guilds[guildId]));
}
