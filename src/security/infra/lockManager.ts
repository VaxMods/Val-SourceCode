import crypto from "node:crypto";
import type { Redis } from "ioredis";

export interface LockManager {
  withLock<T>(key: string, ttlMs: number, task: () => Promise<T>): Promise<T>;
  once(key: string, ttlMs: number): Promise<boolean>;
  sweep(now: number): void;
}

export class MemoryLockManager implements LockManager {
  private readonly chains = new Map<string, Promise<unknown>>();
  private readonly seen = new Map<string, number>();

  constructor(private readonly now: () => number = Date.now) {}

  async withLock<T>(key: string, _ttlMs: number, task: () => Promise<T>): Promise<T> {
    const previous = this.chains.get(key) ?? Promise.resolve();
    const run = previous.then(task, task);
    const settled = run.then(
      () => undefined,
      () => undefined
    );
    this.chains.set(key, settled);
    try {
      return await run;
    } finally {
      if (this.chains.get(key) === settled) this.chains.delete(key);
    }
  }

  async once(key: string, ttlMs: number): Promise<boolean> {
    const current = this.now();
    const expiry = this.seen.get(key);
    if (expiry !== undefined && expiry > current) return false;
    this.seen.set(key, current + ttlMs);
    if (this.seen.size > 100000) this.sweep(current);
    return true;
  }

  sweep(now: number): void {
    for (const [key, expiry] of this.seen) if (expiry <= now) this.seen.delete(key);
  }
}

const RELEASE_SCRIPT = "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";

export class RedisLockManager implements LockManager {
  private readonly local = new MemoryLockManager();

  constructor(
    private readonly redis: Redis,
    private readonly prefix = "vp:lock:"
  ) {}

  async withLock<T>(key: string, ttlMs: number, task: () => Promise<T>): Promise<T> {
    return this.local.withLock(key, ttlMs, async () => {
      const lockKey = this.prefix + key;
      const token = crypto.randomBytes(16).toString("hex");
      const deadline = Date.now() + ttlMs;
      let acquired = false;
      while (!acquired) {
        acquired = (await this.redis.set(lockKey, token, "PX", ttlMs, "NX")) === "OK";
        if (!acquired) {
          if (Date.now() > deadline) throw new Error(`Timed out waiting for lock ${key}`);
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
      }
      try {
        return await task();
      } finally {
        await this.redis.eval(RELEASE_SCRIPT, 1, lockKey, token);
      }
    });
  }

  async once(key: string, ttlMs: number): Promise<boolean> {
    return (await this.redis.set(`${this.prefix}once:${key}`, "1", "PX", ttlMs, "NX")) === "OK";
  }

  sweep(now: number): void {
    this.local.sweep(now);
  }
}
