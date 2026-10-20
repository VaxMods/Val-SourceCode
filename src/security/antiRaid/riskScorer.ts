import type { GuildPolicy } from "../../config/schema.js";

export interface JoinSample {
  userId: string;
  username: string;
  joinedAt: number;
  accountCreatedAt: number;
  hasAvatar: boolean;
  flaggedSpammer: boolean;
}

export type SignalName = keyof GuildPolicy["antiRaid"]["weights"];

export interface RiskSignal {
  name: SignalName;
  points: number;
  detail: string;
}

export interface RiskAssessment {
  score: number;
  signals: RiskSignal[];
  clustered: boolean;
}

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s" };

export function normalizeName(username: string): string {
  const stripped = username
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[\s._-]*\d+$/, "");
  return stripped
    .split("")
    .map((char) => LEET[char] ?? char)
    .join("")
    .replace(/[^a-z]/g, "");
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min((previous[j] as number) + 1, (current[j - 1] as number) + 1, (previous[j - 1] as number) + cost);
    }
    previous = current;
  }
  return previous[b.length] as number;
}

export function similarNames(a: string, b: string): boolean {
  const left = normalizeName(a);
  const right = normalizeName(b);
  if (left.length >= 4 && left === right) return true;
  if (left.length < 6 || right.length < 6) return false;
  const distance = levenshtein(left.slice(0, 32), right.slice(0, 32));
  return 1 - distance / Math.max(left.length, right.length) >= 0.85;
}

const DAY = 86400000;
const CREATION_CLUSTER_MS = 15 * 60000;

export function assessJoin(
  sample: JoinSample,
  recent: readonly JoinSample[],
  settings: GuildPolicy["antiRaid"],
  rejoinAfterAction: boolean,
  now: number
): RiskAssessment {
  const weights = settings.weights;
  const signals: RiskSignal[] = [];
  const ageMs = Math.max(0, now - sample.accountCreatedAt);
  const ageDays = ageMs / DAY;
  if (ageDays < settings.newAccountDays && weights.accountAge > 0) {
    const ratio = ageMs < 3600000 ? 1 : 1 - ageDays / settings.newAccountDays;
    signals.push({ name: "accountAge", points: Math.round(weights.accountAge * ratio), detail: `account is ${ageDays.toFixed(1)} days old` });
  }
  if (!sample.hasAvatar && weights.noAvatar > 0) {
    signals.push({ name: "noAvatar", points: weights.noAvatar, detail: "default avatar" });
  }
  const others = recent.filter((item) => item.userId !== sample.userId);
  const nameMatches = others.filter((item) => similarNames(item.username, sample.username)).length;
  if (nameMatches >= 2 && weights.usernameCluster > 0) {
    signals.push({ name: "usernameCluster", points: weights.usernameCluster, detail: `${nameMatches} recent joiners with a similar username` });
  }
  const creationMatches = others.filter((item) => Math.abs(item.accountCreatedAt - sample.accountCreatedAt) <= CREATION_CLUSTER_MS).length;
  if (creationMatches >= 2 && weights.creationCluster > 0) {
    signals.push({ name: "creationCluster", points: weights.creationCluster, detail: `${creationMatches} recent joiners created within 15 minutes of this account` });
  }
  if (rejoinAfterAction && weights.rejoinAfterAction > 0) {
    signals.push({ name: "rejoinAfterAction", points: weights.rejoinAfterAction, detail: "rejoined after a recent protective measure" });
  }
  if (sample.flaggedSpammer && weights.spammerFlag > 0) {
    signals.push({ name: "spammerFlag", points: weights.spammerFlag, detail: "account carries Discord's spammer flag" });
  }
  const score = Math.min(100, signals.reduce((sum, signal) => sum + signal.points, 0));
  return { score, signals, clustered: signals.some((signal) => signal.name === "usernameCluster" || signal.name === "creationCluster") };
}
