import type { Clock } from "../core/clock.js";

export class FakeClock implements Clock {
  constructor(private current: number = Date.UTC(2026, 9, 15, 12, 0, 0)) {}

  now(): number {
    return this.current;
  }

  async sleep(ms: number): Promise<void> {
    this.current += Math.max(0, ms);
  }

  advance(ms: number): void {
    this.current += ms;
  }

  set(ms: number): void {
    this.current = ms;
  }
}
