import { afterEach, describe, expect, it } from "vitest";
import { guildPolicySchema } from "../src/config/schema.js";
import { bitsOf } from "../src/discord/permissions.js";
import type { MessageSample } from "../src/security/spam/contentRules.js";
import { analyzeLinks, isLookalike } from "../src/security/spam/linkAnalyzer.js";
import type { Simulation } from "../src/simulation/harness.js";
import { methods, simulate } from "./helpers.js";

let sim: Simulation;
let counter = 0n;

afterEach(async () => {
  await sim?.close();
});

const MEMBER = { roleIds: ["400000000000000008"], permissions: bitsOf(["SendMessages"]), isOwner: false };

function message(authorId: string, content: string, overrides: Partial<MessageSample> = {}): MessageSample {
  counter += 1n;
  return {
    id: (810000000000000000n + counter).toString(),
    guildId: sim.ids.guildId,
    channelId: sim.ids.channels.general,
    authorId,
    content,
    mentionCount: 0,
    canMentionEveryone: false,
    createdAt: sim.clock.now(),
    ...overrides
  };
}

describe("link analysis", () => {
  const links = guildPolicySchema.parse({ antiSpam: { links: { blockedDomains: ["*.scam.example"], allowedDomains: ["github.com"] } } }).antiSpam.links;

  it("recognises look-alike domains but not official ones", () => {
    expect(isLookalike("disc0rd-nitro.gift")).toBe(true);
    expect(isLookalike("dlscord.com")).toBe(true);
    expect(isLookalike("steamcommunlty.ru")).toBe(true);
    expect(isLookalike("discord.com")).toBe(false);
    expect(isLookalike("cdn.discordapp.com")).toBe(false);
    expect(isLookalike("example.org")).toBe(false);
  });

  it("classifies links by risk", () => {
    const kinds = (text: string) => analyzeLinks(text, links).map((finding) => finding.kind);
    expect(kinds("see https://login.scam.example/x")).toEqual(["blocked"]);
    expect(kinds("join discord.gg/abcdef")).toEqual(["invite"]);
    expect(kinds("https://bit.ly/3xyz")).toEqual(["shortener"]);
    expect(kinds("https://d\u0456scord.com/gift")).toEqual(["lookalike"]);
    expect(kinds("https://xn--dscord-6ve.com")).toEqual(["malformed"]);
    expect(kinds("https://xn--caf-dma.example")).toEqual(["punycode"]);
    expect(kinds("http://45.12.8.9/payload")).toEqual(["ip"]);
    expect(kinds("https://github.com/org/repo and https://example.org")).toEqual([]);
  });
});

describe("anti-spam service", () => {
  it("does not penalise a normal conversation", async () => {
    sim = await simulate();
    const author = sim.memberIds[0] as string;
    const lines = ["hey everyone", "how was your weekend?", "I finished the report", "lunch at noon?", "sounds good to me", "see you there"];
    for (const line of lines) {
      sim.clock.advance(4000);
      const result = await sim.kernel.antiSpam.onMessage(message(author, line), MEMBER);
      expect(result?.level).toBe("none");
    }
    expect(methods(sim)).not.toContain("deleteMessages");
  });

  it("escalates progressively from warning to timeout, never further", async () => {
    sim = await simulate();
    const author = sim.memberIds[1] as string;
    const levels: string[] = [];
    for (let index = 0; index < 14; index += 1) {
      sim.clock.advance(300);
      const result = await sim.kernel.antiSpam.onMessage(message(author, "buy cheap followers now!!!"), MEMBER);
      if (result && result.level !== "none" && levels[levels.length - 1] !== result.level) levels.push(result.level);
    }
    expect(levels).toEqual(["warn", "delete", "timeout"]);
    expect(methods(sim)).not.toContain("kickMember");
    expect(sim.gateway.callsTo("timeoutMember")).toHaveLength(1);
  });

  it("deletes mass mentions immediately", async () => {
    sim = await simulate();
    const result = await sim.kernel.antiSpam.onMessage(message(sim.memberIds[2] as string, "look", { mentionCount: 12 }), MEMBER);
    expect(result?.violations.map((item) => item.kind)).toContain("mentions");
    expect(methods(sim)).toContain("deleteMessages");
  });

  it("exempts staff members", async () => {
    sim = await simulate();
    const staff = { roleIds: [sim.ids.roles.moderator], permissions: bitsOf(["ManageMessages"]), isOwner: false };
    for (let index = 0; index < 12; index += 1) {
      sim.clock.advance(100);
      expect(await sim.kernel.antiSpam.onMessage(message(sim.ids.rogueId, "announcement"), staff)).toBeNull();
    }
  });

  it("applies and later restores slowmode during a multi-user flood", async () => {
    sim = await simulate();
    for (const author of sim.memberIds.slice(0, 6)) {
      for (let index = 0; index < 9; index += 1) {
        sim.clock.advance(100);
        await sim.kernel.antiSpam.onMessage(message(author, `flood ${index} from ${author}`), MEMBER);
      }
    }
    expect(sim.gateway.channels.get(sim.ids.channels.general)?.rateLimitPerUser).toBe(10);
    sim.clock.advance(11 * 60000);
    await sim.kernel.antiSpam.tick();
    expect(sim.gateway.channels.get(sim.ids.channels.general)?.rateLimitPerUser).toBe(0);
  });

  it("explains why administrators cannot be timed out", async () => {
    sim = await simulate();
    const admin = sim.gateway.addMember({ username: "loud.admin", roleIds: [sim.ids.roles.admin] });
    let last;
    for (let index = 0; index < 14; index += 1) {
      sim.clock.advance(200);
      last = await sim.kernel.antiSpam.onMessage(message(admin.id, "spam spam spam spam"), { roleIds: [], permissions: bitsOf(["SendMessages"]), isOwner: false });
    }
    const timeout = last?.actions.find((action) => action.action === "timeout");
    expect(timeout?.outcome.skipped).toBe(true);
    expect(timeout?.rationale).toMatch(/administrators|above/);
  });
});
