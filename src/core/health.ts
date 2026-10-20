export interface ComponentHealth {
  component: string;
  healthy: boolean;
  reason: string | null;
  since: number;
}

export class HealthMonitor {
  private readonly components = new Map<string, ComponentHealth>();

  constructor(private readonly now: () => number = Date.now) {}

  degraded(component: string, reason: string): boolean {
    const current = this.components.get(component);
    const changed = !current || current.healthy;
    if (changed || current?.reason !== reason) {
      this.components.set(component, { component, healthy: false, reason, since: changed ? this.now() : (current?.since ?? this.now()) });
    }
    return changed;
  }

  healthy(component: string): boolean {
    const current = this.components.get(component);
    const recovered = current !== undefined && !current.healthy;
    if (!current || recovered) this.components.set(component, { component, healthy: true, reason: null, since: this.now() });
    return recovered;
  }

  isHealthy(component: string): boolean {
    return this.components.get(component)?.healthy ?? true;
  }

  snapshot(): ComponentHealth[] {
    return [...this.components.values()].sort((a, b) => a.component.localeCompare(b.component));
  }

  degradedComponents(): ComponentHealth[] {
    return this.snapshot().filter((item) => !item.healthy);
  }
}
