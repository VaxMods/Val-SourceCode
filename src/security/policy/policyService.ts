import type { Logger } from "pino";
import { resolveGuildPolicy, type LoadedConfig } from "../../config/loader.js";
import { getPath, setPath } from "../../config/merge.js";
import { guildPolicySchema, type GlobalSettings, type GuildPolicy } from "../../config/schema.js";
import { validatePolicySemantics } from "../../config/validation.js";
import type { Clock } from "../../core/clock.js";
import { ValidationError, errorMessage } from "../../core/errors.js";
import type { HealthMonitor } from "../../core/health.js";
import type { WhitelistScope } from "../../core/types.js";
import type { ProtectedRoleRecord } from "../../database/repositories/protectedRoleRepository.js";
import type { Repositories } from "../../database/repositories/index.js";
import type { WhitelistEntry } from "../../database/repositories/whitelistRepository.js";
import { bitsOf } from "../../discord/permissions.js";

export interface ProtectedRoleRule {
  roleId: string;
  source: "config" | "discord";
  allowedGranterIds: string[];
  allowedGranterRoleIds: string[];
}

export interface PolicyContext {
  guildId: string;
  policy: GuildPolicy;
  dangerousMask: bigint;
  protectedRoles: Map<string, ProtectedRoleRule>;
  whitelist: WhitelistEntry[];
  runtimeOverrides: Record<string, unknown>;
  revision: number;
  degraded: boolean;
}

export type ConfigSource = Pick<LoadedConfig, "defaults" | "guilds" | "global" | "hash">;

export class PolicyService {
  private readonly cache = new Map<string, { context: PolicyContext; expires: number }>();

  constructor(
    private readonly config: ConfigSource,
    private readonly repos: Repositories,
    private readonly clock: Clock,
    private readonly logger: Logger,
    private readonly health: HealthMonitor,
    private readonly cacheMs = 15000
  ) {}

  get global(): GlobalSettings {
    return this.config.global;
  }

  get configHash(): string {
    return this.config.hash;
  }

  isGuildAllowed(guildId: string): boolean {
    const allowed = this.config.global.allowedGuildIds;
    return allowed.length === 0 || allowed.includes(guildId);
  }

  invalidate(guildId: string): void {
    this.cache.delete(guildId);
  }

  async context(guildId: string): Promise<PolicyContext> {
    const now = this.clock.now();
    const cached = this.cache.get(guildId);
    if (cached && cached.expires > now) return cached.context;
    const context = await this.build(guildId, now);
    this.cache.set(guildId, { context, expires: now + (context.degraded ? 2000 : this.cacheMs) });
    return context;
  }

  async candidate(guildId: string, changes: ReadonlyArray<{ path: string; value: unknown }>): Promise<{ policy: GuildPolicy; overrides: Record<string, unknown>; revision: number }> {
    const stored = await this.repos.settings.get(guildId);
    let overrides = stored?.overrides ?? {};
    for (const change of changes) overrides = setPath(overrides, change.path, change.value);
    const parsed = guildPolicySchema.safeParse(resolveCandidate(this.config, guildId, overrides));
    if (!parsed.success) {
      throw new ValidationError(parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; "));
    }
    const semantic = validatePolicySemantics(parsed.data);
    if (semantic.errors.length > 0) throw new ValidationError(semantic.errors.join("; "));
    return { policy: parsed.data, overrides, revision: stored?.revision ?? 0 };
  }

  async saveOverrides(guildId: string, overrides: Record<string, unknown>, revision: number, updatedBy: string): Promise<void> {
    const saved = await this.repos.settings.save(guildId, overrides, revision, updatedBy, new Date(this.clock.now()).toISOString());
    if (!saved) throw new ValidationError("The configuration was changed at the same time by someone else; try again");
    this.invalidate(guildId);
  }

  currentValue(context: PolicyContext, path: string): unknown {
    return getPath(context.policy as unknown as Record<string, unknown>, path);
  }

  isSecurityAdmin(context: PolicyContext, userId: string): boolean {
    return context.policy.securityAdminIds.includes(userId);
  }

  whitelistFor(context: PolicyContext, subjectId: string, scope: WhitelistScope): WhitelistEntry | null {
    return context.whitelist.find((entry) => entry.subjectId === subjectId && (entry.scopes.includes("all") || entry.scopes.includes(scope))) ?? null;
  }

  isApprovedBot(context: PolicyContext, botId: string): boolean {
    return context.policy.bots.approvedBotIds.includes(botId) || context.whitelist.some((entry) => entry.subjectId === botId && entry.subjectType === "bot");
  }

  private async build(guildId: string, now: number): Promise<PolicyContext> {
    const nowIso = new Date(now).toISOString();
    let overrides: Record<string, unknown> = {};
    let revision = 0;
    let whitelist: WhitelistEntry[] = [];
    let commandRoles: ProtectedRoleRecord[] = [];
    let degraded = false;
    try {
      const [settings, entries, roles] = await Promise.all([
        this.repos.settings.get(guildId),
        this.repos.whitelist.listActive(guildId, nowIso),
        this.repos.protectedRoles.list(guildId)
      ]);
      overrides = settings?.overrides ?? {};
      revision = settings?.revision ?? 0;
      whitelist = entries;
      commandRoles = roles;
      if (this.health.healthy("database")) this.logger.info("Database reachable again");
    } catch (error) {
      degraded = true;
      if (this.health.degraded("database", errorMessage(error))) {
        this.logger.error({ err: errorMessage(error), guildId }, "Policy storage unavailable; using file configuration only");
      }
    }
    const policy = resolveGuildPolicy(this.config, guildId, overrides);
    const protectedRoles = new Map<string, ProtectedRoleRule>();
    for (const roleId of policy.roleProtection.protectedRoleIds) {
      protectedRoles.set(roleId, { roleId, source: "config", allowedGranterIds: [], allowedGranterRoleIds: [] });
    }
    for (const record of commandRoles) {
      const existing = protectedRoles.get(record.roleId);
      protectedRoles.set(record.roleId, {
        roleId: record.roleId,
        source: existing?.source ?? "discord",
        allowedGranterIds: record.allowedGranterIds,
        allowedGranterRoleIds: record.allowedGranterRoleIds
      });
    }
    return {
      guildId,
      policy,
      dangerousMask: bitsOf(policy.roleProtection.dangerousPermissions),
      protectedRoles,
      whitelist,
      runtimeOverrides: overrides,
      revision,
      degraded
    };
  }
}

function resolveCandidate(config: ConfigSource, guildId: string, overrides: Record<string, unknown>): Record<string, unknown> {
  const base = resolveGuildPolicy(config, guildId);
  return mergeOverrides(base as unknown as Record<string, unknown>, overrides);
}

function mergeOverrides(base: Record<string, unknown>, overrides: Record<string, unknown>): Record<string, unknown> {
  let output = base;
  const walk = (prefix: string, value: Record<string, unknown>) => {
    for (const [key, item] of Object.entries(value)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (item !== null && typeof item === "object" && !Array.isArray(item)) walk(path, item as Record<string, unknown>);
      else output = setPath(output, path, item);
    }
  };
  walk("", overrides);
  return output;
}
