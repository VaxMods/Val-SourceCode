import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { dotenvHints, loadDotEnv } from "../src/config/dotenv.js";
import { tempDir } from "./helpers.js";

const BODY = [
  "NODE_ENV=production",
  "",
  "# comment line",
  "DISCORD_TOKEN=abc.def.ghi",
  "DISCORD_CLIENT_ID=1530707788756422716",
  "DATABASE_URL=",
  "ALERT_FALLBACK_WEBHOOK_URL=https://discord.com/api/webhooks/1/x_y-z",
  "EVIDENCE_HMAC_KEY=143ccb1d56fb3d253da0cae2b43bca3815132d8b2fc43f20908834a0a67900f3",
  "QUOTED=\"two words\""
];

function write(name: string, data: Buffer | string): string {
  const file = path.join(tempDir("dotenv"), name);
  fs.writeFileSync(file, data);
  return file;
}

function expectLoaded(file: string): NodeJS.ProcessEnv {
  const target: NodeJS.ProcessEnv = {};
  const result = loadDotEnv(file, target);
  expect(result.file).toBe(path.resolve(file));
  expect(target.DISCORD_TOKEN).toBe("abc.def.ghi");
  expect(target.DISCORD_CLIENT_ID).toBe("1530707788756422716");
  expect(target.EVIDENCE_HMAC_KEY).toHaveLength(64);
  expect(target.ALERT_FALLBACK_WEBHOOK_URL).toBe("https://discord.com/api/webhooks/1/x_y-z");
  expect(target.QUOTED).toBe("two words");
  expect(target.NODE_ENV).toBe("production");
  return target;
}

describe(".env loader", () => {
  it("loads LF and CRLF files", () => {
    expectLoaded(write("lf.env", BODY.join("\n")));
    expectLoaded(write("crlf.env", BODY.join("\r\n")));
  });

  it("loads files with carriage-return-only line endings", () => {
    expectLoaded(write("cr.env", BODY.join("\r")));
  });

  it("loads UTF-8 with BOM, UTF-16 LE and UTF-16 BE files", () => {
    expectLoaded(write("bom.env", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(BODY.join("\r\n"), "utf8")])));
    expectLoaded(write("utf16le.env", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(BODY.join("\r\n"), "utf16le")])));
    const be = Buffer.from(BODY.join("\r\n"), "utf16le");
    be.swap16();
    expectLoaded(write("utf16be.env", Buffer.concat([Buffer.from([0xfe, 0xff]), be])));
  });

  it("removes invisible characters around keys and values", () => {
    const dirty = BODY.map((line) => (line.startsWith("DISCORD_TOKEN") ? ` ${line} ​` : line.startsWith("DISCORD_CLIENT_ID") ? `​\t${line}` : line));
    expectLoaded(write("dirty.env", dirty.join("\n")));
  });

  it("keeps non-empty system values but fills empty ones", () => {
    const file = write("precedence.env", BODY.join("\n"));
    const target: NodeJS.ProcessEnv = { DISCORD_TOKEN: "from-system", DISCORD_CLIENT_ID: "" };
    const result = loadDotEnv(file, target);
    expect(target.DISCORD_TOKEN).toBe("from-system");
    expect(target.DISCORD_CLIENT_ID).toBe("1530707788756422716");
    expect(result.ignored).toEqual(["DISCORD_TOKEN"]);
    expect(dotenvHints(result).join(" ")).toMatch(/system value wins: DISCORD_TOKEN/);
  });

  it("reports invalid lines and a missing file", () => {
    const result = loadDotEnv(write("invalid.env", "DISCORD_TOKEN abc\n=novalue\nOK=1"), {});
    expect(result.invalidLines).toEqual([1, 2]);
    expect(result.loaded).toEqual(["OK"]);
    const missing = loadDotEnv(path.join(tempDir("dotenv-missing"), ".env"), {});
    expect(missing.file).toBeNull();
    expect(dotenvHints(missing)[0]).toMatch(/No \.env file found/);
  });

  it("never modifies the file on disk", () => {
    const file = write("readonly.env", BODY.join("\r"));
    const before = fs.readFileSync(file);
    loadDotEnv(file, {});
    expect(fs.readFileSync(file).equals(before)).toBe(true);
  });
});
