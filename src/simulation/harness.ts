import crypto from "node:crypto";
import type { Logger } from "pino";
import { parseConfigObject } from "../config/loader.js";
import { deepMerge } from "../config/merge.js";
import { createSilentLogger } from "../core/logger.js";
import { HealthMonitor } from "../core/health.js";
import { migrateToLatest, openDatabase, type DatabaseHandle } from "../database/connection.js";
import { createRepositories, type Repositories } from "../database/repositories/index.js";
import { categoryOf, type AuditEvent } from "../discord/auditEvent.js";
import type { MemberInfo } from "../discord/gateway.js";
import type { FallbackTransport } from "../security/alerts/alertService.js";
import { MemoryCounterStore } from "../security/infra/counterStore.js";
import { MemoryLockManager } from "../security/infra/lockManager.js";
import { createKernel, type SecurityKernel } from "../security/kernel.js";
import { FakeClock } from "./fakeClock.js";
import { buildFixture, fixturePolicy, type FixtureIds } from "./fixture.js";
import type { InMemoryGateway } from "./inMemoryGateway.js";

export interface SimulationOptions {
  policy?: Record<string, unknown>;
  replacePolicy?: boolean;
  global?: Record<string, unknown>;
  logger?: Logger;
  hmacKey?: Buffer;
  files?: { evidenceMirror: string | null; evidenceFallback: string | null; alertFallback: string | null };
  fallbackWebhookUrl?: string | null;
  transport?: FallbackTransport;
}

export interface Simulation {
  kernel: SecurityKernel;
  gateway: InMemoryGateway;
  clock: FakeClock;
  ids: FixtureIds;
  memberIds: string[];
  database: DatabaseHandle;
  repos: Repositories;
  webhookPosts: unknown[];
  audit(event: Pick<AuditEvent, "actionType"> & Partial<AuditEvent>): Promise<AuditEvent>;
  join(partial: Partial<MemberInfo> & { username: string }): Promise<MemberInfo>;
  close(): Promise<void>;
}

export async function createSimulation(options: SimulationOptions = {}): Promise<Simulation> {
  const clock = new FakeClock();
  const { gateway, ids, memberIds } = buildFixture(() => clock.now());
  const database = openDatabase({ driver: "sqlite", path: ":memory:" });
  await migrateToLatest(database.db);
  const repos = createRepositories(database.db);
  const defaults = options.replacePolicy ? (options.policy ?? {}) : deepMerge(fixturePolicy(ids), options.policy);
  const parsed = parseConfigObject({ version: 1, global: options.global ?? {}, defaults, guilds: {} }, "simulation configuration");
  const webhookPosts: unknown[] = [];
  const transport: FallbackTransport = options.transport ?? {
    async postWebhook(_url, body) {
      webhookPosts.push(body);
      return true;
    }
  };
  const kernel = createKernel({
    gateway,
    config: { ...parsed, hash: "simulation" },
    repos,
    counters: new MemoryCounterStore(),
    locks: new MemoryLockManager(() => clock.now()),
    clock,
    logger: options.logger ?? createSilentLogger(),
    health: new HealthMonitor(() => clock.now()),
    hmacKey: options.hmacKey ?? crypto.randomBytes(32),
    files: options.files ?? { evidenceMirror: null, evidenceFallback: null, alertFallback: null },
    fallbackWebhookUrl: options.fallbackWebhookUrl === undefined ? "https://discord.com/api/webhooks/1/simulation" : options.fallbackWebhookUrl,
    transport
  });
  await kernel.lockdown.initialize();
  let auditCounter = 0n;
  return {
    kernel,
    gateway,
    clock,
    ids,
    memberIds,
    database,
    repos,
    webhookPosts,
    async audit(event) {
      auditCounter += 1n;
      const recorded = gateway.recordAudit({
        id: (700000000000000000n + auditCounter).toString(),
        executorId: event.executorId ?? null,
        targetId: event.targetId ?? null,
        createdAt: clock.now(),
        ...event,
        category: categoryOf(event.actionType)
      });
      await kernel.dispatcher.dispatch(recorded);
      return recorded;
    },
    async join(partial) {
      const member = gateway.addMember({ joinedAt: clock.now(), ...partial });
      await kernel.antiRaid.onMemberJoin(member);
      return member;
    },
    async close() {
      await database.close();
    }
  };
}
