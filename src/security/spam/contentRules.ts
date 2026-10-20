import crypto from "node:crypto";
import type { GuildPolicy } from "../../config/schema.js";
import { analyzeLinks } from "./linkAnalyzer.js";

export type ViolationKind = "burst" | "duplicate" | "mentions" | "everyone-attempt" | "caps" | "characters" | "link" | "thread-flood";

export interface SpamViolation {
  kind: ViolationKind;
  severity: "low" | "medium" | "high";
  strikes: number;
  detail: string;
  deleteMessage: boolean;
}

export interface MessageSample {
  id: string;
  guildId: string;
  channelId: string;
  authorId: string;
  content: string;
  mentionCount: number;
  canMentionEveryone: boolean;
  createdAt: number;
}

export function contentHash(content: string): string | null {
  const normalized = content.toLowerCase().replace(/\s+/g, " ").trim();
  if (normalized.length < 5) return null;
  return crypto.createHash("sha1").update(normalized).digest("hex").slice(0, 16);
}

export function longestRun(content: string): number {
  let best = 0;
  let current = 0;
  let previous = "";
  for (const char of content) {
    current = char === previous ? current + 1 : 1;
    previous = char;
    if (current > best) best = current;
  }
  return best;
}

export function analyzeContent(message: MessageSample, settings: GuildPolicy["antiSpam"]): SpamViolation[] {
  const violations: SpamViolation[] = [];
  const content = message.content;
  if (message.mentionCount >= settings.maxMentions) {
    violations.push({ kind: "mentions", severity: "high", strikes: 2, detail: `${message.mentionCount} mentions in one message`, deleteMessage: true });
  }
  if (!message.canMentionEveryone && /@(everyone|here)\b/i.test(content)) {
    violations.push({ kind: "everyone-attempt", severity: "medium", strikes: 1, detail: "attempted @everyone/@here without permission", deleteMessage: false });
  }
  const letters = content.replace(/[^\p{L}]/gu, "");
  if (letters.length >= settings.caps.minLength) {
    const upper = letters.replace(/[^\p{Lu}]/gu, "").length;
    if (upper / letters.length >= settings.caps.ratio) {
      violations.push({ kind: "caps", severity: "low", strikes: 1, detail: `${Math.round((upper / letters.length) * 100)}% capital letters`, deleteMessage: false });
    }
  }
  const run = longestRun(content);
  const combining = (content.match(/[̀-ͯ҉᪰-᫿⃐-⃿]/g) ?? []).length;
  if (run >= settings.maxRepeatedChars || combining > 30) {
    violations.push({ kind: "characters", severity: "low", strikes: 1, detail: run >= settings.maxRepeatedChars ? `${run} repeated characters` : `${combining} combining marks`, deleteMessage: true });
  }
  for (const finding of analyzeLinks(content, settings.links)) {
    violations.push({
      kind: "link",
      severity: finding.severity,
      strikes: finding.severity === "high" ? 2 : 1,
      detail: `${finding.kind} link (${finding.host})`,
      deleteMessage: finding.severity !== "low"
    });
  }
  return violations;
}
