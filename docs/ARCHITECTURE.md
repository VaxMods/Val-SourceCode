# Architecture

## Goals that shaped the design

1. **Real security over appearances.** Every response must be possible with the actual Discord API and the bot's actual permissions; anything else is reported, not faked.
2. **No false positives by construction.** Detection and response are separated. Responses require an explicit policy, automatic mode and a sufficient attribution confidence. Unknown authors are never punished.
3. **Testability.** Every security service talks to Discord through a small port (`DiscordGateway`). Production uses the discord.js implementation; tests and `/security test` use an in-memory implementation. The same kernel factory wires both.
4. **Graceful degradation.** Database down, Redis down, alert channel deleted, Discord API errors or missing permissions degrade features and raise alerts; they never stop the other protections.

## Layers

```
┌───────────────────────────────────────────────────────────────────────┐
│ Discord gateway (discord.js Client)                                   │
│  guildAuditLogEntryCreate · memberAdd/Update · roleUpdate · messages  │
│  threads · bans · guildCreate/Delete · interactions                   │
└──────────────┬───────────────────────────────────────────┬────────────┘
               │ src/discord/events.ts                     │ interactions
               ▼                                           ▼
┌──────────────────────────────┐            ┌──────────────────────────────┐
│ AuditDispatcher (dedupe by   │            │ CommandRouter                │
│ audit entry id)              │            │  rate limit → access level → │
└───┬───────┬───────┬──────┬───┘            │  handler → confirmation      │
    ▼       ▼       ▼      ▼                └──────────────┬───────────────┘
 AntiNuke RoleGuard BotGuard IntegrationGuard TamperGuard  │
    │       │       │      │            AntiRaid  AntiSpam  Honeypot
    └───────┴───────┴──────┴──────────────┬───────────────────┘
                                          ▼
        ┌──────────────────────────────────────────────────────────┐
        │ Shared services                                           │
        │  PolicyService (file + runtime overrides + whitelist +   │
        │  protected roles) · IncidentService · EvidenceLog (HMAC  │
        │  chain) · AlertService (channel → webhook → file) ·      │
        │  LockdownService · ContainmentResponder · hierarchy rules │
        │  CounterStore / LockManager (memory or Redis)            │
        └──────────────┬────────────────────────────┬──────────────┘
                       ▼                            ▼
             DiscordGateway port            Repositories (Kysely)
          (discord.js or in-memory)       SQLite or PostgreSQL
```

## Event flow example: unauthorized Administrator grant

1. A moderator gives the `Admin` role to an accomplice. Discord executes it.
2. Discord sends `GUILD_AUDIT_LOG_ENTRY_CREATE` (type `MEMBER_ROLE_UPDATE`, `$add` change, executor, target). `events.ts` normalizes it into an `AuditEvent` and hands it to the `AuditDispatcher`, which deduplicates by entry ID and fans out to every handler.
3. `RoleGuard` reloads the role (current permissions, not its name), decides whether it is sensitive (protected list or dangerous permissions), reloads the recipient and the granter, and asks `authorizeRoleGrant` whether the policy allows it (owner, security admin, allowed granters, granter roles, whitelist, lockdown restriction).
4. Not allowed → `IncidentService.open` persists the incident, appends evidence, and sends an alert immediately.
5. Response, only in automatic mode and with sufficient confidence: revoke the role from the recipient if the hierarchy allows it; remove only the granter's roles that grant Manage Roles or Administrator when confidence is high and the policy says so. Every action is recorded with its rationale and result, and a follow-up alert summarizes them.
6. In parallel, `guildMemberUpdate` sees the new role. `RoleGuard.onMemberRolesAdded` waits for the correlation delay; if the audit path already handled the grant it stops, otherwise it fetches the audit log itself and attributes the grant, or reports it as unattributed (alert only).
7. `AntiNukeService` also counts the `memberRoleUpdate` for mass-change detection.

## Modules

| Path | Responsibility |
| --- | --- |
| `src/config` | Environment schema and `.env` loader, policy schema (strict zod objects), semantic validation (refuses dangerous combinations), settings registry (kind, owner-only flag, weakening rules for every setting editable from Discord), safe deep merge |
| `src/core` | Shared types, logger with redaction, secret scrubber, health monitor, clock abstraction, errors |
| `src/database` | Kysely connection (SQLite or PostgreSQL), migration, typed repositories. Every query is parameterized by Kysely; there is no string-built SQL |
| `src/discord` | Gateway port and DTOs, discord.js implementation, audit-entry normalization, permission catalog and feature requirements, client factory, event wiring |
| `src/security/policy` | Effective policy per server (cached), access levels, trust and grant authorization; `SettingsService` is the single entry point for every configuration change (plan, validate against the server, classify weakening, check access, commit, record, announce) |
| `src/security/evidence` | Tamper-evident log: per-server sequence, HMAC-SHA256 chaining, JSONL mirror, fallback file, retention anchors, verification |
| `src/security/alerts` | Embed formatting with mention neutralization, alert channel delivery, fallback webhook and file, throttling |
| `src/security/incidents` | Incident lifecycle and response recording |
| `src/security/response` | Proportional containment: remove only roles granting the abused permission, kick malicious bots |
| `src/security/lockdown` | Bounded lockdown with persistence, expiry and safe restoration |
| `src/security/antiRaid` | Risk scoring, adaptive raid detector, graduated measures |
| `src/security/antiNuke` | Threshold engine per actor and category, unattributed spikes, recovery hints |
| `src/security/roles` | Sensitive grant control, permission escalation, privileged role creation, hierarchy changes |
| `src/security/bots` | Bot registry, logical quarantine, risk assessment |
| `src/security/integrations` | Webhooks, integrations, command permission changes |
| `src/security/spam` | Content rules, link analysis, sanction ladder, flood slowmode |
| `src/security/honeypot` | Trap signals, correlation, decoy safety |
| `src/security/tamper` | Takeover and log-tampering signals |
| `src/security/scanner` | Security report |
| `src/security/backup` | Structural snapshots and recovery |
| `src/security/infra` | Sliding-window counters and locks (memory or Redis) |
| `src/commands` | `/security` definition, router, confirmations, handlers; `panel/` holds the configuration panel (sessions, views, modals, controller) |
| `src/jobs` | Scheduler: lockdown expiry, raid cooldown, slowmode restore, alert throttle flush, retention, integrity checks, snapshots, heartbeat |
| `src/simulation` | In-memory gateway, fake clock, fixture, harness and rule tester |
| `src/cli` | Operational tools |

## Data model

| Table | Content |
| --- | --- |
| `guild_settings` | Runtime overrides per server with optimistic revision |
| `whitelist_entries` | Approvals with scopes, reason, author, expiry and revocation (never deleted) |
| `protected_roles` | Roles protected from Discord with allowed granters and granter roles |
| `incidents` | Incident record, status, confidence, details |
| `security_events` | Evidence chain: `(guild_id, seq)` primary key, `prev_hash`, `hash` |
| `log_anchors` | Last purged sequence and hash, so the chain stays verifiable after retention |
| `lockdowns` | Active and past lockdown state with what must be restored |
| `bot_registry` | Bot approval status and risk assessment |
| `guild_snapshots` | Structural snapshots with SHA-256 integrity hash |

All identifiers are stored as text (Discord snowflakes exceed JavaScript's safe integers), timestamps as ISO-8601 UTC strings, and structured data as JSON text, which keeps the schema identical on SQLite and PostgreSQL.

## Technical choices

| Choice | Reason |
| --- | --- |
| TypeScript, native ESM, `verbatimModuleSyntax`, strict mode with `noUncheckedIndexedAccess` | Catch mistakes at compile time; every discord.js call is checked against the installed typings |
| discord.js 14.27.0 (latest stable) | `guildAuditLogEntryCreate`, `Guild#setIncidentActions`, `Guild#disableInvites`, `SlashCommandBuilder#setContexts`, `MessageFlags.Ephemeral` all verified in the installed typings |
| Kysely | One query builder for SQLite and PostgreSQL, parameterized queries, migrations |
| better-sqlite3 | Reliable embedded database with WAL mode and online backups |
| zod 4 | Strict schemas and readable validation errors for environment and policy |
| pino | Fast structured JSON logging, redaction paths, file reopen for logrotate |
| ioredis (optional) | Sliding windows with sorted sets, `SET NX PX` locks with token release |
| Vitest | Fast offline tests with the in-memory gateway |

## Concurrency and idempotency

- Audit events are deduplicated by entry ID (`once`), responses per incident are opened once per actor/category window, and grant handling is deduplicated per audit entry so a **re-grant after a revocation is always evaluated again**.
- Evidence appends are serialized per server by a lock; on a sequence conflict the head is reloaded and the append retried.
- Lockdown activation and deactivation are serialized per server.
- With Redis, counters and locks are shared across processes; without it, a single process per bot token is expected (the recommended deployment).
