import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { sql } from "kysely";
import { afterEach, describe, expect, it } from "vitest";
import type { Simulation } from "../src/simulation/harness.js";
import { fakeBotToken, fakeWebhookUrl, simulate, tempDir } from "./helpers.js";

let sim: Simulation;

afterEach(async () => {
  await sim?.close();
});

async function fill(count: number): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    sim.clock.advance(1000);
    await sim.kernel.evidence.append({ guildId: sim.ids.guildId, eventType: "test.event", severity: "info", evidence: { index } });
  }
}

describe("tamper-evident evidence log", () => {
  it("verifies an intact chain", async () => {
    sim = await simulate();
    await fill(25);
    const result = await sim.kernel.evidence.verify(sim.ids.guildId);
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(25);
  });

  it("detects a modified record", async () => {
    sim = await simulate();
    await fill(10);
    await sql`update security_events set evidence_json = '{"index":999}' where seq = 4`.execute(sim.database.db);
    const result = await sim.kernel.evidence.verify(sim.ids.guildId);
    expect(result.ok).toBe(false);
    expect(result.brokenAtSeq).toBe(4);
    expect(result.reason).toMatch(/HMAC/);
  });

  it("detects a deleted record", async () => {
    sim = await simulate();
    await fill(10);
    await sql`delete from security_events where seq = 6`.execute(sim.database.db);
    const result = await sim.kernel.evidence.verify(sim.ids.guildId);
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/sequence gap/);
  });

  it("cannot be re-forged without the HMAC key", async () => {
    sim = await simulate();
    await fill(5);
    const forgedHash = crypto.createHash("sha256").update("forged").digest("hex");
    await sql`update security_events set hash = ${forgedHash} where seq = 5`.execute(sim.database.db);
    expect((await sim.kernel.evidence.verify(sim.ids.guildId)).ok).toBe(false);
  });

  it("keeps the chain verifiable after a retention purge", async () => {
    sim = await simulate();
    await fill(10);
    sim.clock.advance(40 * 86400000);
    await fill(5);
    const removed = await sim.kernel.evidence.purgeOlderThan(sim.ids.guildId, sim.clock.now() - 30 * 86400000);
    expect(removed).toBe(10);
    const anchor = await sim.repos.events.anchor(sim.ids.guildId);
    expect(anchor?.seq).toBe(10);
    await fill(2);
    const result = await sim.kernel.evidence.verify(sim.ids.guildId);
    expect(result.ok).toBe(true);
    expect(result.firstSeq).toBe(11);
  });

  it("redacts secrets and mirrors records to JSONL", async () => {
    const dir = tempDir("evidence");
    const mirror = path.join(dir, "evidence.jsonl");
    sim = await simulate({ files: { evidenceMirror: mirror, evidenceFallback: null, alertFallback: null } });
    await sim.kernel.evidence.append({
      guildId: sim.ids.guildId,
      eventType: "test.secret",
      severity: "info",
      evidence: {
        note: `posted ${fakeWebhookUrl("123456789012345678", "SuperSecretWebhookToken_abc")}`,
        token: fakeBotToken()
      }
    });
    const stored = await sim.repos.events.recent(sim.ids.guildId, 1);
    const serialized = JSON.stringify(stored);
    expect(serialized).not.toContain("SuperSecretWebhookToken_abc");
    expect(serialized).not.toContain("abcdefghijklmnopqrstuvwxyz0123456789ABCD");
    const line = fs.readFileSync(mirror, "utf8").trim();
    expect(JSON.parse(line).hash).toBe(stored[0]?.hash);
  });
});
