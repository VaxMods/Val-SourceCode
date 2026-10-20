import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { decodeHmacKey, parseEnv } from "../src/config/env.js";
import { loadConfigFile, parseConfigObject } from "../src/config/loader.js";
import { deepMerge, setPath } from "../src/config/merge.js";
import { coerceSettingValue, getSetting } from "../src/config/settings.js";
import { guildPolicySchema } from "../src/config/schema.js";
import { validatePolicySemantics } from "../src/config/validation.js";
import { ConfigurationError, ValidationError } from "../src/core/errors.js";
import { fakeBotToken, tempDir } from "./helpers.js";

const VALID_ENV = {
  DISCORD_TOKEN: fakeBotToken(),
  DISCORD_CLIENT_ID: "123456789012345678",
  EVIDENCE_HMAC_KEY: "a".repeat(64)
};

describe("configuration file", () => {
  it("starts with built-in defaults when no configuration file exists", () => {
    const loaded = loadConfigFile(path.join(tempDir("no-config"), "missing.json"), { optional: true });
    expect(loaded.fileFound).toBe(false);
    expect(loaded.global.allowedGuildIds).toEqual([]);
    expect(() => loadConfigFile(path.join(tempDir("no-config"), "missing.json"))).toThrow(/not found/);
  });

  it("ships an example configuration that validates", () => {
    const loaded = loadConfigFile(path.resolve("config/val-protection.example.json"));
    expect(loaded.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("applies secure defaults", () => {
    const policy = guildPolicySchema.parse({});
    expect(policy.mode).toBe("monitor");
    expect(policy.roleProtection.revokeWhenActorUnknown).toBe(false);
    expect(policy.antiRaid.suspectAction).not.toBe("kick");
    expect(policy.logging.retentionDays).toBeGreaterThanOrEqual(30);
  });

  it("rejects unknown keys so typos are not silently ignored", () => {
    expect(() => parseConfigObject({ version: 1, defaults: { antiRiad: { enabled: false } } })).toThrow(ConfigurationError);
  });

  it("rejects invalid identifiers and out-of-range values", () => {
    expect(() => parseConfigObject({ version: 1, defaults: { alertChannelId: "not-an-id" } })).toThrow(/snowflake/);
    expect(() => parseConfigObject({ version: 1, defaults: { logging: { retentionDays: 3 } } })).toThrow(ConfigurationError);
    expect(() => parseConfigObject({ version: 1, defaults: { antiNuke: { thresholds: { memberBan: { limit: 0 } } } } })).toThrow(ConfigurationError);
    expect(() => parseConfigObject({ version: 1, defaults: { roleProtection: { dangerousPermissions: ["Superpower"] } } })).toThrow(/permission/);
  });

  it("refuses dangerous combinations", () => {
    expect(() => parseConfigObject({ version: 1, defaults: { antiRaid: { suspectAction: "kick", actOnlyDuringRaid: false } } })).toThrow(/kick/);
    expect(() => parseConfigObject({ version: 1, defaults: { antiRaid: { quarantineRoleId: "400000000000000007" }, honeypot: { decoyRoleIds: ["400000000000000007"] } } })).toThrow(/decoy/);
    expect(() => parseConfigObject({ version: 1, defaults: { roleProtection: { dangerousPermissions: ["ManageRoles"] } } })).toThrow(/Administrator/);
    expect(() => parseConfigObject({ version: 1, defaults: { antiSpam: { links: { allowedDomains: ["example.com"], blockedDomains: ["example.com"] } } } })).toThrow(/both allowed and blocked/);
  });

  it("warns about settings that cause false positives", () => {
    const report = validatePolicySemantics(guildPolicySchema.parse({ antiRaid: { minJoinsForRaid: 3 }, antiNuke: { thresholds: { roleDelete: { limit: 1 } } } }));
    expect(report.errors).toEqual([]);
    expect(report.warnings.join(" ")).toMatch(/minJoinsForRaid/);
    expect(report.warnings.join(" ")).toMatch(/roleDelete/);
  });

  it("refuses a world-writable configuration file", () => {
    if (process.platform === "win32") return;
    const dir = tempDir("config");
    const file = path.join(dir, "config.json");
    fs.writeFileSync(file, JSON.stringify({ version: 1 }));
    fs.chmodSync(file, 0o666);
    expect(() => loadConfigFile(file)).toThrow(/world-writable/);
  });

  it("ignores prototype pollution keys when merging", () => {
    const merged = deepMerge(JSON.parse('{"__proto__":{"polluted":true},"a":{"b":1}}') as Record<string, unknown>);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(merged).toEqual({ a: { b: 1 } });
    expect(() => setPath({}, "__proto__.x", 1)).toThrow();
  });
});

describe("environment", () => {
  it("accepts a valid environment", () => {
    expect(parseEnv(VALID_ENV).DATABASE_DRIVER).toBe("sqlite");
  });

  it("rejects missing or weak secrets", () => {
    expect(() => parseEnv({ ...VALID_ENV, DISCORD_TOKEN: "short" })).toThrow(ConfigurationError);
    expect(() => parseEnv({ ...VALID_ENV, EVIDENCE_HMAC_KEY: "abcd" })).toThrow(/32 bytes/);
    expect(() => parseEnv({ ...VALID_ENV, DATABASE_DRIVER: "postgres" })).toThrow(/DATABASE_URL/);
    expect(() => parseEnv({ ...VALID_ENV, ALERT_FALLBACK_WEBHOOK_URL: "https://evil.example/hook" })).toThrow(/webhook/);
    expect(decodeHmacKey(Buffer.alloc(32, 7).toString("base64")).length).toBe(32);
  });
});

describe("invalid input through the settings registry", () => {
  it("coerces values strictly", () => {
    expect(coerceSettingValue(getSetting("antiRaid.minJoinsForRaid"), "12")).toBe(12);
    expect(() => coerceSettingValue(getSetting("antiRaid.minJoinsForRaid"), "12; DROP TABLE incidents")).toThrow(ValidationError);
    expect(() => coerceSettingValue(getSetting("mode"), "chaos")).toThrow(ValidationError);
    expect(coerceSettingValue(getSetting("alertChannelId"), "none")).toBeNull();
    expect(() => coerceSettingValue(getSetting("alertChannelId"), "<#123>")).toThrow(ValidationError);
    expect(() => coerceSettingValue(getSetting("securityAdminIds"), ["123", "not-an-id"])).toThrow(ValidationError);
    expect(coerceSettingValue(getSetting("antiSpam.links.blockedDomains"), "Scam.Example\n\n*.bad.example, scam.example")).toEqual(["scam.example", "*.bad.example"]);
    expect(() => getSetting("global.allowedGuildIds")).toThrow(/cannot be changed/);
  });
});
