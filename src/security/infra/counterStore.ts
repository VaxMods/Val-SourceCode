import crypto from "node:crypto";
import type { Redis } from "ioredis";

export interface CounterStore {
  hit(key: string, windowMs: number, now: number, weight?: number): Promise<number>;
  count(key: string, windowMs: number, now: number): Promise<number>;
  addDistinct(key: string, member: string, windowMs: number, now: number): Promise<number>;
  clear(key: string): Promise<void>;
  sweep(now: number): void;
}

interface Bucket {
  stamps: number[];
  windowMs: number;
}

interface DistinctBucket {
  members: Map<string, number>;
  windowMs: number;
}

export class MemoryCounterStore implements CounterStore {
  private readonly buckets = new Map<string, Bucket>();
  private readonly distinct = new Map<string, DistinctBucket>();

  constructor(private readonly maxKeys = 200000) {}

  async hit(key: string, windowMs: number, now: number, weight = 1): Promise<number> {
    const bucket = this.touch(this.buckets, key, () => ({ stamps: [], windowMs }));
    bucket.windowMs = Math.max(bucket.windowMs, windowMs);
    for (let index = 0; index < Math.max(1, Math.floor(weight)); index += 1) bucket.stamps.push(now);
    return this.prune(bucket.stamps, now - windowMs);
  }

  async count(key: string, windowMs: number, now: number): Promise<number> {
    const bucket = this.buckets.get(key);
    if (!bucket) return 0;
    return bucket.stamps.filter((stamp) => stamp > now - windowMs).length;
  }

  async addDistinct(key: string, member: string, windowMs: number, now: number): Promise<number> {
    const bucket = this.touch(this.distinct, key, () => ({ members: new Map(), windowMs }));
    bucket.windowMs = Math.max(bucket.windowMs, windowMs);
    bucket.members.set(member, now);
    for (const [id, stamp] of bucket.members) if (stamp <= now - windowMs) bucket.members.delete(id);
    return bucket.members.size;
  }

  async clear(key: string): Promise<void> {
    this.buckets.delete(key);
    this.distinct.delete(key);
  }

  sweep(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (this.prune(bucket.stamps, now - bucket.windowMs) === 0) this.buckets.delete(key);
    }
    for (const [key, bucket] of this.distinct) {
      for (const [id, stamp] of bucket.members) if (stamp <= now - bucket.windowMs) bucket.members.delete(id);
      if (bucket.members.size === 0) this.distinct.delete(key);
    }
  }

  size(): number {
    return this.buckets.size + this.distinct.size;
  }

  private touch<T>(map: Map<string, T>, key: string, create: () => T): T {
    let value = map.get(key);
    if (value) {
      map.delete(key);
    } else {
      value = create();
      if (map.size >= this.maxKeys) {
        const oldest = map.keys().next().value;
        if (oldest !== undefined) map.delete(oldest);
      }
    }
    map.set(key, value);
    return value;
  }

  private prune(stamps: number[], threshold: number): number {
    let drop = 0;
    while (drop < stamps.length && (stamps[drop] as number) <= threshold) drop += 1;
    if (drop > 0) stamps.splice(0, drop);
    return stamps.length;
  }
}

export class RedisCounterStore implements CounterStore {
  constructor(
    private readonly redis: Redis,
    private readonly prefix = "vp:counter:"
  ) {}

  async hit(key: string, windowMs: number, now: number, weight = 1): Promise<number> {
    const redisKey = this.prefix + key;
    const members: Array<string | number> = [];
    for (let index = 0; index < Math.max(1, Math.floor(weight)); index += 1) {
      members.push(now, `${now}:${crypto.randomBytes(6).toString("hex")}`);
    }
    const result = await this.redis
      .multi()
      .zadd(redisKey, ...members)
      .zremrangebyscore(redisKey, "-inf", now - windowMs)
      .zcard(redisKey)
      .pexpire(redisKey, windowMs)
      .exec();
    return Number(result?.[2]?.[1] ?? 0);
  }

  async count(key: string, windowMs: number, now: number): Promise<number> {
    return this.redis.zcount(this.prefix + key, `(${now - windowMs}`, "+inf");
  }

  async addDistinct(key: string, member: string, windowMs: number, now: number): Promise<number> {
    const redisKey = `${this.prefix}distinct:${key}`;
    const result = await this.redis
      .multi()
      .zadd(redisKey, now, member)
      .zremrangebyscore(redisKey, "-inf", now - windowMs)
      .zcard(redisKey)
      .pexpire(redisKey, windowMs)
      .exec();
    return Number(result?.[2]?.[1] ?? 0);
  }

  async clear(key: string): Promise<void> {
    await this.redis.del(this.prefix + key, `${this.prefix}distinct:${key}`);
  }

  sweep(): void {}
}
