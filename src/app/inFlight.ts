export class InFlightTracker {
  private readonly tasks = new Set<Promise<unknown>>();

  track(task: Promise<unknown>): void {
    this.tasks.add(task);
    void task.finally(() => this.tasks.delete(task));
  }

  get size(): number {
    return this.tasks.size;
  }

  async drain(timeoutMs: number): Promise<boolean> {
    if (this.tasks.size === 0) return true;
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs);
    });
    const settled = Promise.allSettled([...this.tasks]).then(() => true);
    const result = await Promise.race([settled, timeout]);
    if (timer) clearTimeout(timer);
    return result;
  }
}
