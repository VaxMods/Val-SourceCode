import { domainToUnicode } from "node:url";
import type { GuildPolicy } from "../../config/schema.js";
import { levenshtein } from "../antiRaid/riskScorer.js";

export type LinkKind = "blocked" | "invite" | "shortener" | "lookalike" | "punycode" | "ip" | "malformed";

export interface LinkFinding {
  host: string;
  kind: LinkKind;
  severity: "low" | "medium" | "high";
}

const OFFICIAL_DOMAINS = [
  "discord.com",
  "discord.gg",
  "discordapp.com",
  "discordapp.net",
  "discord.media",
  "discord.new",
  "discord.gift",
  "discordstatus.com",
  "steamcommunity.com",
  "steampowered.com",
  "steamstatic.com"
];

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly", "buff.ly", "tiny.cc", "s.id", "v.gd", "t.ly"];

const URL_PATTERN = /\bhttps?:\/\/[^\s<>()"']+/gi;
const BARE_INVITE = /(?:^|[\s(<])((?:www\.)?(?:discord(?:app)?\.com\/invite|discord\.gg)\/[\w-]+)/gi;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "|": "l" };

const CONFUSABLES: Record<string, string> = {
  "\u0430": "a",
  "\u0435": "e",
  "\u043e": "o",
  "\u0440": "p",
  "\u0441": "c",
  "\u0443": "y",
  "\u0445": "x",
  "\u0456": "i",
  "\u0458": "j",
  "\u0455": "s",
  "\u0501": "d",
  "\u04bb": "h",
  "\u03bf": "o",
  "\u03b1": "a",
  "\u03b9": "i",
  "\u0131": "i",
  "\u0261": "g"
};

export function matchesDomain(host: string, domain: string): boolean {
  if (domain.startsWith("*.")) {
    const base = domain.slice(2);
    return host === base || host.endsWith(`.${base}`);
  }
  return host === domain || host.endsWith(`.${domain}`);
}

function skeleton(label: string): string {
  return label
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .split("")
    .map((char) => CONFUSABLES[char] ?? LEET[char] ?? char)
    .join("")
    .replace(/rn/g, "m")
    .replace(/[^a-z]/g, "");
}

export function isLookalike(host: string): boolean {
  if (OFFICIAL_DOMAINS.some((domain) => matchesDomain(host, domain))) return false;
  const unicode = host.includes("xn--") ? domainToUnicode(host) || host : host;
  const labels = unicode.toLowerCase().split(".").slice(0, -1);
  for (const label of labels) {
    const value = skeleton(label);
    if (value.length < 4) continue;
    if (value.includes("discord") || value.includes("nitro") || value.includes("steamcommun") || value.includes("steampower")) return true;
    if (value.length >= 6 && levenshtein(value.slice(0, 20), "discord") <= 2) return true;
    if (value.length >= 10 && levenshtein(value.slice(0, 24), "steamcommunity") <= 3) return true;
  }
  return false;
}

export function extractHosts(content: string): Array<{ host: string; invite: boolean; malformed?: boolean }> {
  const results: Array<{ host: string; invite: boolean; malformed?: boolean }> = [];
  const seen = new Set<string>();
  const add = (raw: string) => {
    try {
      const url = new URL(raw.startsWith("http") ? raw : `https://${raw}`);
      const host = url.hostname.toLowerCase().replace(/\.$/, "");
      const invite = (matchesDomain(host, "discord.gg") && url.pathname.length > 1) || (/^(?:www\.)?discord(?:app)?\.com$/.test(host) && url.pathname.startsWith("/invite/"));
      const key = `${host}|${invite}`;
      if (!seen.has(key)) {
        seen.add(key);
        results.push({ host, invite });
      }
    } catch {
      const host = raw.replace(/^https?:\/\//i, "").split(/[/?#]/)[0]?.toLowerCase() ?? raw;
      if (!seen.has(`${host}|malformed`)) {
        seen.add(`${host}|malformed`);
        results.push({ host: host.slice(0, 120), invite: false, malformed: true });
      }
    }
  };
  for (const match of content.slice(0, 4000).matchAll(URL_PATTERN)) {
    if (results.length >= 20) break;
    add(match[0]);
  }
  for (const match of content.slice(0, 4000).matchAll(BARE_INVITE)) {
    if (results.length >= 20) break;
    if (match[1]) add(match[1]);
  }
  return results;
}

export function analyzeLinks(content: string, settings: GuildPolicy["antiSpam"]["links"]): LinkFinding[] {
  const findings: LinkFinding[] = [];
  for (const { host, invite, malformed } of extractHosts(content)) {
    if (malformed) {
      const lookalike = settings.flagLookalikes && isLookalike(host);
      findings.push({ host, kind: lookalike ? "lookalike" : "malformed", severity: lookalike ? "high" : "medium" });
      continue;
    }
    if (settings.allowedDomains.some((domain) => matchesDomain(host, domain))) continue;
    if (settings.blockedDomains.some((domain) => matchesDomain(host, domain))) {
      findings.push({ host, kind: "blocked", severity: "high" });
      continue;
    }
    if (invite) {
      if (settings.flagInvites) findings.push({ host, kind: "invite", severity: "medium" });
      continue;
    }
    if (settings.flagLookalikes && isLookalike(host)) {
      findings.push({ host, kind: "lookalike", severity: "high" });
      continue;
    }
    if (host.split(".").some((label) => label.startsWith("xn--"))) {
      findings.push({ host, kind: "punycode", severity: "medium" });
      continue;
    }
    if (settings.flagIpHosts && (IPV4.test(host) || host.startsWith("["))) {
      findings.push({ host, kind: "ip", severity: "medium" });
      continue;
    }
    if (settings.flagShorteners && SHORTENERS.some((domain) => matchesDomain(host, domain))) {
      findings.push({ host, kind: "shortener", severity: "low" });
    }
  }
  return findings;
}
