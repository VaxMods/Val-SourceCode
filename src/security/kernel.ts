import type { Logger } from "pino";
import type { Clock } from "../core/clock.js";
import type { HealthMonitor } from "../core/health.js";
import type { Repositories } from "../database/repositories/index.js";
import type { DiscordGateway } from "../discord/gateway.js";
import { AlertService, fetchTransport, type FallbackTransport } from "./alerts/alertService.js";
import { AntiNukeService } from "./antiNuke/antiNukeService.js";
import { AntiRaidService } from "./antiRaid/antiRaidService.js";
import { AuditDispatcher } from "./auditDispatcher.js";
import { SnapshotService } from "./backup/snapshotService.js";
import { BotGuard } from "./bots/botGuard.js";
import { EvidenceLog } from "./evidence/evidenceLog.js";
import { HoneypotService } from "./honeypot/honeypotService.js";
import { IncidentService } from "./incidents/incidentService.js";
import type { CounterStore } from "./infra/counterStore.js";
import type { LockManager } from "./infra/lockManager.js";
import { IntegrationGuard } from "./integrations/integrationGuard.js";
import { LockdownService } from "./lockdown/lockdownService.js";
import { PolicyService, type ConfigSource } from "./policy/policyService.js";
import { SettingsService } from "./policy/settingsService.js";
import { ContainmentResponder } from "./response/containment.js";
import { RoleGuard } from "./roles/roleGuard.js";
import { PermissionScanner } from "./scanner/permissionScanner.js";
import { AntiSpamService } from "./spam/antiSpamService.js";
import { TamperGuard } from "./tamper/tamperGuard.js";

export interface KernelDependencies {
  gateway: DiscordGateway;
  config: ConfigSource;
  repos: Repositories;
  counters: CounterStore;
  locks: LockManager;
  clock: Clock;
  logger: Logger;
  health: HealthMonitor;
  hmacKey: Buffer;
  files: { evidenceMirror: string | null; evidenceFallback: string | null; alertFallback: string | null };
  fallbackWebhookUrl: string | null;
  transport?: FallbackTransport;
}

export interface SecurityKernel {
  deps: KernelDependencies;
  policies: PolicyService;
  settings: SettingsService;
  evidence: EvidenceLog;
  alerts: AlertService;
  incidents: IncidentService;
  responder: ContainmentResponder;
  lockdown: LockdownService;
  antiRaid: AntiRaidService;
  antiNuke: AntiNukeService;
  roleGuard: RoleGuard;
  botGuard: BotGuard;
  integrations: IntegrationGuard;
  antiSpam: AntiSpamService;
  honeypot: HoneypotService;
  tamper: TamperGuard;
  scanner: PermissionScanner;
  snapshots: SnapshotService;
  dispatcher: AuditDispatcher;
}

export function createKernel(deps: KernelDependencies): SecurityKernel {
  const { gateway, repos, counters, locks, clock, logger, health } = deps;
  const policies = new PolicyService(deps.config, repos, clock, logger.child({ module: "policy" }), health);
  const evidence = new EvidenceLog(repos.events, deps.hmacKey, locks, clock, logger.child({ module: "evidence" }), health, {
    mirrorPath: deps.files.evidenceMirror,
    fallbackPath: deps.files.evidenceFallback
  });
  const alerts = new AlertService(gateway, policies, clock, logger.child({ module: "alerts" }), health, {
    webhookUrl: deps.fallbackWebhookUrl,
    filePath: deps.files.alertFallback,
    transport: deps.transport ?? fetchTransport
  });
  const settings = new SettingsService(gateway, policies, repos, evidence, alerts, clock, logger.child({ module: "settings" }));
  const incidents = new IncidentService(repos.incidents, evidence, alerts, clock, logger.child({ module: "incidents" }), health);
  const responder = new ContainmentResponder(gateway);
  const lockdown = new LockdownService(repos.lockdowns, gateway, policies, evidence, alerts, locks, clock, logger.child({ module: "lockdown" }), health);
  const snapshots = new SnapshotService(gateway, repos.snapshots, policies, evidence, lockdown, locks, clock, logger.child({ module: "snapshots" }));
  const honeypot = new HoneypotService(gateway, policies, incidents, evidence, alerts, counters, locks, clock, logger.child({ module: "honeypot" }));
  const antiRaid = new AntiRaidService(gateway, policies, incidents, evidence, alerts, lockdown, counters, locks, clock, logger.child({ module: "anti-raid" }));
  const antiNuke = new AntiNukeService(gateway, policies, incidents, evidence, responder, lockdown, counters, locks, snapshots, clock, logger.child({ module: "anti-nuke" }));
  const roleGuard = new RoleGuard(gateway, policies, incidents, evidence, responder, lockdown, locks, honeypot, clock, logger.child({ module: "role-guard" }));
  const botGuard = new BotGuard(gateway, policies, repos.bots, incidents, evidence, responder, lockdown, counters, locks, clock, logger.child({ module: "bot-guard" }));
  const integrations = new IntegrationGuard(gateway, policies, incidents, evidence, logger.child({ module: "integrations" }));
  const antiSpam = new AntiSpamService(gateway, policies, incidents, evidence, alerts, lockdown, counters, locks, clock, logger.child({ module: "anti-spam" }));
  const tamper = new TamperGuard(gateway, policies, incidents, evidence, alerts, locks, clock, logger.child({ module: "tamper" }));
  const scanner = new PermissionScanner(gateway, policies, repos.bots, clock);
  const dispatcher = new AuditDispatcher(
    [
      { name: "anti-nuke", handler: antiNuke },
      { name: "role-guard", handler: roleGuard },
      { name: "bot-guard", handler: botGuard },
      { name: "integrations", handler: integrations },
      { name: "tamper", handler: tamper }
    ],
    policies,
    locks,
    logger.child({ module: "dispatcher" })
  );
  return { deps, policies, settings, evidence, alerts, incidents, responder, lockdown, antiRaid, antiNuke, roleGuard, botGuard, integrations, antiSpam, honeypot, tamper, scanner, snapshots, dispatcher };
}
