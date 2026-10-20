import type { GuildPolicy } from "../../config/schema.js";
import type { JoinSample } from "./riskScorer.js";

export interface ScoredJoin extends JoinSample {
  score: number;
  clustered: boolean;
}

export type RaidKind = "surge" | "suspicious-wave";

export interface RaidAssessment {
  joinsInWindow: number;
  threshold: number;
  baseline: number;
  suspiciousInWindow: number;
  suspiciousInSlowWindow: number;
  clusteredInWindow: number;
  raidScore: number;
  detected: RaidKind | null;
}

export class RaidDetector {
  private joins: ScoredJoin[] = [];
  private baseline: number | null = null;
  private bucketStart: number | null = null;
  private bucketCount = 0;

  record(join: ScoredJoin, settings: GuildPolicy["antiRaid"], frozen: boolean): void {
    this.roll(join.joinedAt, settings, frozen);
    this.bucketCount += 1;
    this.joins.push(join);
    this.trim(join.joinedAt, settings);
  }

  recent(now: number, settings: GuildPolicy["antiRaid"]): ScoredJoin[] {
    this.trim(now, settings);
    return [...this.joins];
  }

  evaluate(now: number, settings: GuildPolicy["antiRaid"], frozen: boolean): RaidAssessment {
    this.roll(now, settings, frozen);
    this.trim(now, settings);
    const windowMs = settings.windowSeconds * 1000;
    const inWindow = this.joins.filter((join) => join.joinedAt > now - windowMs);
    const slowWindowMs = settings.slowWaveWindowMinutes * 60000;
    const inSlowWindow = this.joins.filter((join) => join.joinedAt > now - slowWindowMs);
    const baseline = this.baseline ?? 0;
    const adaptiveThreshold = settings.adaptive.enabled ? Math.ceil(baseline * settings.adaptive.multiplier) : 0;
    const threshold = Math.max(settings.minJoinsForRaid, adaptiveThreshold);
    const suspicious = inWindow.filter((join) => join.score >= settings.suspectScoreThreshold).length;
    const suspiciousSlow = inSlowWindow.filter((join) => join.score >= settings.suspectScoreThreshold).length;
    const clustered = inWindow.filter((join) => join.clustered).length;
    const joins = inWindow.length;
    const rate = Math.min(1, joins / threshold) * 50;
    const ratio = joins > 0 ? (suspicious / joins) * 30 : 0;
    const cluster = Math.min(1, clustered / Math.max(3, Math.ceil(threshold / 2))) * 20;
    const raidScore = Math.round(rate + ratio + cluster);
    let detected: RaidKind | null = null;
    if (joins >= threshold && raidScore >= settings.raidScoreThreshold) detected = "surge";
    else if (suspiciousSlow >= settings.slowWaveSuspectCount) detected = "suspicious-wave";
    return {
      joinsInWindow: joins,
      threshold,
      baseline: Math.round(baseline * 100) / 100,
      suspiciousInWindow: suspicious,
      suspiciousInSlowWindow: suspiciousSlow,
      clusteredInWindow: clustered,
      raidScore,
      detected
    };
  }

  private roll(now: number, settings: GuildPolicy["antiRaid"], frozen: boolean): void {
    const windowMs = settings.windowSeconds * 1000;
    if (this.bucketStart === null) {
      this.bucketStart = now;
      return;
    }
    if (now < this.bucketStart + windowMs) return;
    const alpha = 1 - Math.pow(0.5, settings.windowSeconds / (settings.adaptive.halfLifeMinutes * 60));
    const elapsed = Math.floor((now - this.bucketStart) / windowMs);
    if (!frozen) {
      const current = this.baseline ?? 0;
      const blended = alpha * this.bucketCount + (1 - alpha) * current;
      const capped = Math.min(blended, current * settings.adaptive.maxGrowthPerBucket + 0.5);
      const idleBuckets = Math.min(elapsed - 1, 10000);
      this.baseline = capped * Math.pow(1 - alpha, Math.max(0, idleBuckets));
    }
    this.bucketStart += elapsed * windowMs;
    this.bucketCount = 0;
  }

  private trim(now: number, settings: GuildPolicy["antiRaid"]): void {
    const horizon = Math.max(settings.windowSeconds * 1000, settings.slowWaveWindowMinutes * 60000);
    if (this.joins.length > 0 && (this.joins[0] as ScoredJoin).joinedAt <= now - horizon) {
      this.joins = this.joins.filter((join) => join.joinedAt > now - horizon);
    }
    if (this.joins.length > 5000) this.joins = this.joins.slice(-5000);
  }
}
