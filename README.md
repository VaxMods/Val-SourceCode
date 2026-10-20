# Val Protection

[![CI](https://github.com/Vax-Bex/Val-SourceCode/actions/workflows/ci.yml/badge.svg)](https://github.com/Vax-Bex/Val-SourceCode/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Val Protection is a defensive Discord bot that protects a server against raids, malicious bots, server takeovers ("nukes"), privilege abuse and automated attacks. It is written in TypeScript on top of discord.js 14, stores its state in SQLite or PostgreSQL, and can optionally use Redis for distributed counters and locks.

Val Protection is built around one principle: **be honest about what Discord allows**. Discord does not let any bot block an action *before* it happens. Val Protection detects actions as soon as Discord reports them, identifies the author with an explicit confidence level, responds proportionally within the role hierarchy, records tamper-evident evidence and keeps humans in the loop whenever there is doubt. It never pretends to restrict the server owner, to undelete deleted objects, or to bypass Discord's permission hierarchy.

---

## Contents

1. [Features](#features)
2. [What Val Protection cannot do](#what-val-protection-cannot-do)
3. [Requirements](#requirements)
4. [Discord Developer Portal setup](#discord-developer-portal-setup)
5. [Preparing your server](#preparing-your-server)
6. [Installation on Linux](#installation-on-linux)
7. [Installation on Windows](#installation-on-windows)
8. [Configuring from Discord](#configuring-from-discord)
9. [Configuration](#configuration)
10. [Registering the slash commands](#registering-the-slash-commands)
11. [First run: from monitor to automatic](#first-run-from-monitor-to-automatic)
12. [Slash commands](#slash-commands)
13. [Access model](#access-model)
14. [Testing](#testing)
15. [Operations: backups, logs, integrity](#operations-backups-logs-integrity)
16. [Project structure](#project-structure)
17. [Further documentation](#further-documentation)

---

## Features

| Module | What it does |
| --- | --- |
| **Anti-raid** | Scores every join with several signals (account age, default avatar, username clusters including leetspeak variants, creation-time clusters, rejoin after a measure, Discord spammer flag). Detects join surges against an adaptive baseline (EWMA with capped growth so attackers cannot slowly "train" it) and slow waves of suspicious accounts. Applies graduated measures (quarantine role, timeout, kick only above a high score during a confirmed raid). **Never bans.** |
| **Anti-nuke** | Per-actor, per-category sliding windows over audit-log events: channel/role create/delete/update, overwrites, bans, kicks, prunes, member role updates, webhooks, bot additions, integrations, server settings, command permissions. Thresholds are configurable and tighten automatically during lockdown. |
| **Anti mass-ban / mass-kick** | Same engine, with an additional unattributed spike detector based on ban events when the audit log cannot name the author (alert only, never action). |
| **Privileged role protection** | Detects sensitive role grants (protected roles or any role carrying dangerous permissions), checks the policy, revokes unauthorized grants and removes **only** the granter's role-management access when attribution confidence is high. Detects permission escalation on roles, privileged role creation and hierarchy changes. |
| **Anti-bot** | Unapproved bots enter a logical quarantine (pending review) with a risk assessment. Not being approved never means "malicious". Removal is only automatic when the policy says so and the adder is unauthorized and identified with high confidence. |
| **Permission engine and scanner** | `/security scan` inspects effective permissions (never role names), @everyone, hidden administrator roles, roles above the bot, cumulative privileges across roles, dangerous channel overwrites, 2FA requirement, verification level and Val Protection's own configuration. |
| **Webhooks and integrations** | Unauthorized webhook creation, modification or deletion, integration changes, and changes to who can use Val Protection's commands. Webhook URLs and tokens are never logged. |
| **Anti-spam / anti-flood** | Bursts, duplicates (including cross-channel), mass mentions, caps, character floods, thread floods, and link analysis (blocked domains, invites, shorteners, raw IPs, punycode, Discord/Steam look-alikes including Unicode homographs). Progressive ladder: warn → delete → timeout + staff alert. Multi-user floods trigger temporary slowmode that is restored automatically. |
| **Honeypot** | Passive, harmless decoys: decoy roles without permissions, decoy channels, forbidden command patterns, unauthorized security command attempts, forged or foreign confirmation buttons. Signals are correlated over time to separate honest mistakes from malicious behaviour. Decoys are guaranteed to stay unprivileged. |
| **Takeover protection** | Detects deletion of the alert channel or of Val Protection's messages, removal of the bot's roles or permissions, deletion of security roles, configuration changes (including file changes between restarts) and attempts to weaken protection, which can require the owner. |
| **Lockdown** | Automatic or manual. Raises the verification level, pauses invites through Discord's incident actions (which expire on Discord's side even if the bot dies), quarantines new members, restricts sensitive role grants and tightens thresholds. Always time-bounded with automatic expiry and safe restoration. |
| **Evidence and logging** | Structured JSON logs with secret redaction, plus a per-server **HMAC hash chain** of security events in the database, mirrored to an append-only JSONL file. Retention purges keep the chain verifiable through anchors. Alerts go to a private channel with a fallback webhook and fallback file. |
| **Recovery** | Periodic structural snapshots (roles, channels, overwrites) with integrity hashes and `/security recover` to recreate missing roles and channels after confirmation. Deleted content cannot be restored, and Val Protection says so. |
| **Configuration panel** | `/security panel` configures every server setting from Discord with role, channel and member pickers, toggles and forms. Changes are validated against the real server, weakening changes need confirmation (and the owner by default), and everything is recorded and announced. |
| **Simulation** | `/security test` replays attack scenarios against **your** thresholds on a synthetic in-memory server. Nothing touches your real server. |

## What Val Protection cannot do

These are Discord platform limits, not missing features. See [docs/DISCORD_API_LIMITS.md](docs/DISCORD_API_LIMITS.md) for the full list.

- It cannot prevent an action before Discord executes it. It reacts after the event, usually within a second.
- It cannot restrict, demote, time out or kick the **server owner**.
- It cannot act on members or roles at or above its own highest role.
- It cannot add or remove a permission it does not hold itself. Without Administrator (which it intentionally does not request) it cannot strip Administrator from a role: it raises a critical incident, restricts the account that made the change, and asks for manual action on the role.
- It cannot time out members who have Administrator.
- It cannot undelete channels, roles, messages or webhooks. Recovery recreates structure with new IDs.
- Audit-log attribution can be missing or delayed. When the author is unknown, Val Protection alerts and waits for a human instead of punishing anyone.

## Requirements

- Node.js **22.12 or newer** (LTS 22 or 24 recommended).
- npm 10 or newer.
- No compiler: `better-sqlite3` ships prebuilt binaries for Linux (glibc and musl), macOS and Windows on x64 and arm64. The project `.npmrc` sets `ignore-scripts=true`, so no dependency can run install scripts (supply-chain hardening, and it avoids an npm bug that forces a native rebuild when installing from the lockfile). On another platform, run `npm rebuild better-sqlite3 --ignore-scripts=false` with a C/C++ toolchain.
- Optional: PostgreSQL 14+ for larger installations, Redis 6.2+ for multi-instance counters and locks.

Pinned versions (verified on 2026-10-15): discord.js 14.27.0, Kysely 0.29.6, better-sqlite3 13.0.3, pg 8.23.1, ioredis 6.0.0, pino 10.4.0, zod 4.6.7, TypeScript 7.0.2, Vitest 5.0.5.

## Discord Developer Portal setup

1. Open <https://discord.com/developers/applications> and create an application named **Val Protection**.
2. In **Bot**:
   - Reset and copy the token into `DISCORD_TOKEN`. Never commit it, never paste it in Discord.
   - Disable **Public Bot** so nobody else can invite your instance.
   - Enable the privileged intents **Server Members Intent** and **Message Content Intent**. Leave Presence Intent disabled.
3. In **General Information**, copy the **Application ID** into `DISCORD_CLIENT_ID`.
4. Invite the bot with the scopes `bot` and `applications.commands` and the permission integer `1100317060274`:

   ```
   https://discord.com/oauth2/authorize?client_id=YOUR_APPLICATION_ID&scope=bot%20applications.commands&permissions=1100317060274
   ```

### Gateway intents

| Intent | Privileged | Why |
| --- | --- | --- |
| Guilds | no | Roles, channels and their updates |
| Guild Members | **yes** | Join events (anti-raid), member role updates (fallback grant detection), member scan |
| Guild Moderation | no | `guildAuditLogEntryCreate` (live audit log with authors) and ban events |
| Guild Messages | no | Anti-spam, honeypot channels, alert message deletion |
| Message Content | **yes** | Content-based spam and link analysis, forbidden command traps |

### Bot permissions

Val Protection works with the minimum set below and **must not be given Administrator**. Each missing permission only disables the related feature; `/security status` and the startup alert list what is degraded.

| Permission | Used for |
| --- | --- |
| View Channels, Send Messages, Embed Links, Attach Files | Alerts in the private security channel, reports |
| View Audit Log | Identifying who performed an action (attribution) |
| Manage Roles | Revoking unauthorized grants, restricting abusers, quarantine role, reverting permission escalations, recovery |
| Moderate Members | Timeouts (raid suspects, spam, honeypot escalation) |
| Kick Members | Removing a malicious bot, optional raid kicks |
| Manage Server | Lockdown: verification level and invite pause |
| Manage Channels | Temporary flood slowmode, recovery of channels |
| Manage Webhooks | Optional deletion of unauthorized webhooks |
| Manage Messages, Read Message History | Deleting spam |

Ban Members is deliberately **not** requested: Val Protection never bans.

## Preparing your server

1. **Role hierarchy.** Drag the `Val Protection` role above every role it must be able to revoke (moderator and administrator roles you want protected). Anything above it is out of reach; the scanner reports it.
2. **Alert channel.** Create a private channel visible only to the security team and Val Protection. You will choose it in `/security panel` → General.
3. **Quarantine role.** Create a role with **no permissions**, deny *View Channel* for it on public categories and allow one `#quarantine` channel. Place it below Val Protection. You will choose it in `/security panel` → Anti-raid.
4. **Decoys (optional).** Create a decoy role without any permission (for example offered in onboarding as "Staff applicant") and/or a decoy channel. You will choose them in `/security panel` → Honeypot.
5. **Two-factor requirement.** As the owner, enable *Require 2FA for moderator actions* (Server Settings → Safety Setup). Val Protection cannot enable it for you.
6. **Fallback webhook.** Create a webhook in a channel of a *different* server (for example a private ops server) and set `ALERT_FALLBACK_WEBHOOK_URL`. It receives alerts when the alert channel is unreachable or the bot is removed.

## Installation on Linux

```bash
sudo apt-get update && sudo apt-get install -y git build-essential
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

git clone https://github.com/Vax-Bex/Val-SourceCode.git
cd Val-SourceCode
npm ci
npm run build
npm test

cp .env.example .env
chmod 600 .env
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Put the generated value in `EVIDENCE_HMAC_KEY`, fill `DISCORD_TOKEN`, `DISCORD_CLIENT_ID` and `DEV_GUILD_ID`, then:

```bash
npm run check-config
npm run deploy-commands
npm start
```

Then, in Discord, the server owner runs `/security panel` and configures everything from there (see [Configuring from Discord](#configuring-from-discord)). No configuration file is needed.

For a production VPS with systemd, a dedicated user, sandboxing, log rotation and daily backups, follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Installation on Windows

Install Node.js 22 LTS from <https://nodejs.org> (the installer can add the build tools if prompted). Then in PowerShell:

```powershell
git clone https://github.com/Vax-Bex/Val-SourceCode.git
cd Val-SourceCode
npm ci
npm run build
npm test

Copy-Item .env.example .env
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
notepad .env

npm run check-config
npm run deploy-commands
npm start
```

Then run `/security panel` in Discord as the server owner.

Restrict `.env` to your account (`icacls .env /inheritance:r /grant:r "$env:USERNAME:(R,W)"`). To run as a service on Windows, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#windows-service).

## Configuring from Discord

Everything that concerns a server is configured with **`/security panel`**, an interactive panel visible only to you:

| Section | What you set |
| --- | --- |
| General | Mode (monitor / automatic), alert channel, role pinged on high alerts, owner approval for weakening changes, test alert |
| Access | Security administrators, auditor roles (owner only), staff roles |
| Anti-raid | Quarantine role, measure for suspects, on/off, automatic lockdown, thresholds and measures (forms) |
| Anti-nuke | Limit and window for each of the 20 action types, response, minimum confidence, automatic lockdown |
| Role protection | Protected roles, people allowed to grant every protected role, granters per role, revocation options |
| Bots and webhooks | Approved bots, who may add bots, who may manage webhooks, what to do with unapproved ones |
| Anti-spam | Exempt roles and channels, limits, blocked and allowed domains, link rules, flood slowmode |
| Honeypot | Decoy roles and channels, escalation, forbidden command traps |
| Lockdown and retention | Verification level, lockdown actions, maximum duration, evidence retention, snapshots |
| Whitelist | Approve a person or bot for a scope (optionally time-limited), revoke approvals |

Roles, channels and members are chosen in Discord's own pickers, so there is no ID to copy. On first use the home screen shows a setup checklist (alert channel, security administrators, quarantine role, mode).

Safety rules applied to every change, whether it comes from the panel or a command:

- Each choice is checked against the real server: Val Protection must be able to post in the alert channel, the quarantine role must be below Val Protection and without dangerous permissions, decoy roles must have no privilege, security administrators must be people and approved bots must be bots, and so on. Invalid choices are refused with the reason.
- **Only the server owner** can change security administrators, auditor roles and the owner-approval setting.
- Changes that **weaken** protection (turning a protection off, switching to monitor, raising a threshold, shortening a window, adding someone to a trusted list, removing a protected or decoy role, moving or removing the alert channel, lowering retention) require a confirmation click and, while *Owner approval for weakening changes* is on, the server owner.
- Every change is recorded in the tamper-evident evidence log and announced in the alert channel ("Configuration changed" or "Protection weakened"); refused attempts are recorded and announced too. Moving the alert channel is also announced in the old channel.
- Auditors see the panel in read-only mode; a forged interaction is refused server-side.

## Configuration

Two layers:

- **Environment variables** (`.env`, see [.env.example](.env.example)) hold secrets and infrastructure: token, database, Redis, HMAC key, fallback webhook, paths. Val Protection reads `.env` itself (no Node flag needed) and tolerates Windows quirks: UTF-16 or BOM encodings, any line ending, invisible spaces copied with the values. Variables already defined in the system environment take precedence, and the startup log says so.
- **The optional configuration file** (`config/val-protection.json`) is only needed for process-wide settings (`allowedGuildIds`, command rate limit, scheduler intervals) and a few advanced tuning keys (raid signal weights, adaptive baseline). Without it, built-in defaults apply. When present, it provides the defaults on top of which the panel's choices are applied. Every key is validated at startup with strict schemas (unknown keys are rejected) and semantic rules (dangerous combinations are refused, risky ones are reported).

| Variable | Required | Description |
| --- | --- | --- |
| `ENV_FILE` | no | Path of the environment file (default `.env` in the current folder). Set it in the system environment, not in the file itself |
| `DISCORD_TOKEN` | yes | Bot token |
| `DISCORD_CLIENT_ID` | yes | Application ID |
| `DEV_GUILD_ID` | no | Server where `npm run deploy-commands` registers the command instantly |
| `CONFIG_PATH` | no | Optional policy file path (default `./config/val-protection.json`) |
| `DATABASE_DRIVER` | no | `sqlite` (default) or `postgres` |
| `SQLITE_PATH` | no | SQLite file (default `./data/val-protection.db`) |
| `DATABASE_URL` | postgres | `postgres://user:password@host:5432/db` |
| `REDIS_URL` | no | Enables Redis counters and locks |
| `EVIDENCE_HMAC_KEY` | yes | At least 32 random bytes (hex or base64). Keep it outside the database: it is what makes the evidence chain unforgeable |
| `ALERT_FALLBACK_WEBHOOK_URL` | recommended | Discord webhook in another server for fallback alerts |
| `LOG_LEVEL`, `LOG_DIR`, `BACKUP_DIR`, `BACKUP_KEEP` | no | Logging and backups |
| `MIGRATE_ON_START` | no | Apply migrations at startup (default `true`) |

The complete reference of every policy key, its default and its effect is in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Registering the slash commands

```bash
npm run deploy-commands
npm run deploy-commands:global
```

The first registers `/security` on `DEV_GUILD_ID` instantly (recommended for testing). The second registers it globally (propagation can take up to an hour). Run it again after every update that adds or changes subcommands. The command is hidden by default from members without *Manage Server*; Val Protection still applies its own access control on every call.

## First run: from monitor to automatic

1. Start in monitor mode (the default). Val Protection detects, alerts and records, but takes no action. Configure the server with `/security panel`.
2. Run `/security scan` and fix critical and high findings (hierarchy, @everyone, hidden admin roles, missing permissions).
3. Run `/security test` to see how your thresholds react to simulated attacks.
4. Watch alerts for a few days and tune thresholds for your server's normal activity.
5. Switch Mode to automatic in `/security panel` → General.

## Slash commands

| Command | Access | Confirmation | Description |
| --- | --- | --- | --- |
| `/security panel` | auditor (read-only) / security admin / owner | for weakening and owner-only changes | Interactive configuration panel for every server setting |
| `/security status` | auditor | – | Mode, lockdown, raid state, protections, degraded features, health, evidence head |
| `/security scan` | security admin | – | Full security analysis with a JSON report |
| `/security lockdown reason [minutes]` | security admin | – | Activate lockdown immediately (protective, so no confirmation delay) |
| `/security unlock reason` | security admin | yes | End lockdown and restore what Val Protection changed |
| `/security logs [source] [severity] [limit]` | auditor | – | Recent incidents, evidence records, or integrity verification |
| `/security config [key] [value]` | auditor (view) / security admin (change) | yes | Show or change one setting directly (autocomplete on the key); lists are edited in the panel |
| `/security whitelist add target scope reason [hours]` | security admin (scope `all`: owner) | yes | Approve a person or bot for a scope, optionally time-limited |
| `/security whitelist remove target reason` | security admin | yes | Revoke every approval of a person or bot |
| `/security roles` | auditor | – | Sensitive and protected roles with hierarchy warnings |
| `/security protect-role role action [granter] [granter-role]` | security admin | yes | Protect a role and define who may grant it |
| `/security incident id` | auditor | – | Incident details, linked evidence timeline, JSON export |
| `/security test [scenario]` | security admin | – | Simulate attacks against your rules on a synthetic server |
| `/security backup-status` | auditor | – | Snapshots, difference with the latest snapshot, database backups, integrity |
| `/security recover [snapshot]` | security admin | yes | Recreate missing roles and channels from a snapshot |

Every invocation, refusal and confirmed action is written to the evidence log. Confirmations are bound to the invoking user, single-use and expire after 60 seconds; pressing someone else's confirmation is a honeypot signal. Commands are rate limited per user.

## Access model

| Level | Who | Defined where |
| --- | --- | --- |
| owner | The server owner | Discord |
| security admin | Security administrators | `/security panel` → Access, by the owner only (or the optional configuration file) |
| auditor | Holders of an auditor role | `/security panel` → Access, by the owner only (or the optional configuration file) |
| none | Everyone else, including Discord administrators not listed above | – |

A compromised Discord administrator account therefore cannot reconfigure Val Protection, cannot add itself as a security admin, and cannot erase the evidence log. A compromised security administrator cannot weaken protection without the owner while *Owner approval for weakening changes* is on, and every attempt is announced.

## Testing

```bash
npm test
npm run typecheck
```

The suite (123 tests) runs fully offline with an in-memory Discord gateway and an in-memory SQLite database. It covers every scenario of the specification: simulated raid, wave of suspicious accounts, mass ban, mass kick, forbidden Administrator grant, protected role permission change, unapproved bot, mass channel deletion, database failure, Discord API unavailability, invalid input, legitimate admin action, unattributed role grant, plus evidence tampering, retention, redaction, lockdown, spam, honeypot, scanner, recovery, confirmations, every setting change rule, and the configuration panel (every view rendered against Discord's component limits for each access level, and complete click-through flows with simulated interactions).

On GitHub, the workflow in `.github/workflows/ci.yml` runs the typecheck, the tests, the build and a dependency audit on Linux and Windows with Node 22 and 24 for every push and pull request.

To validate on Discord, use a **private test server** you own, never production:

1. Invite a separate test application with the same permissions.
2. Create test accounts (or ask trusted helpers) and reproduce scenarios from [docs/TESTING.md](docs/TESTING.md).
3. Keep monitor mode first, check alerts, then switch the test server to automatic in `/security panel`.

## Operations: backups, logs, integrity

| Task | Command |
| --- | --- |
| Validate configuration | `npm run check-config` |
| Apply migrations | `npm run migrate` |
| Back up the database (SQLite online backup or `pg_dump`) | `npm run backup` |
| Test the latest backup in a scratch copy | `npm run restore-test` |
| Verify every evidence chain | `npm run verify-logs` (exit code 2 when broken) |

Logs are JSON lines on stdout and in `LOG_DIR/val-protection.log` (reopened on `SIGHUP` for logrotate). The evidence mirror is `LOG_DIR/evidence.jsonl`; fallback files are `evidence-fallback.jsonl` and `alerts-fallback.jsonl`.

## Project structure

```
val-protection/
├── config/                 example policy file (generated from the schema defaults)
├── deploy/                 systemd service, backup timer, logrotate, production env example
├── docs/                   architecture, API limits, threat model, configuration, deployment, review, checklist
├── src/
│   ├── app/                bootstrap, startup verification, graceful shutdown
│   ├── cli/                deploy-commands, migrate, backup, restore-test, verify-logs, check-config
│   ├── commands/           /security definition, router, access control, confirmations, handlers, configuration panel
│   ├── config/             environment and policy schemas, semantic validation, settings registry, .env loader
│   ├── core/               logger, redaction, errors, health, clock, shared types
│   ├── database/           Kysely connection, migrations, repositories (parameterized queries only)
│   ├── discord/            gateway port, discord.js implementation, events, audit normalization, permissions
│   ├── jobs/               scheduler (expiry, retention, integrity, snapshots, heartbeat)
│   ├── security/           every protection module, wired by kernel.ts
│   └── simulation/         in-memory gateway, fixture, harness, rule tester used by tests and /security test
└── tests/                  Vitest suite
```

## Further documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) – layers, data flow, technical choices
- [docs/DISCORD_API_LIMITS.md](docs/DISCORD_API_LIMITS.md) – what Discord allows, feature by feature
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) – assets, adversaries, mitigations, residual risks
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) – every policy key
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) – VPS, systemd, PostgreSQL, Redis, Windows service, updates
- [docs/TESTING.md](docs/TESTING.md) – automated tests and manual scenarios on a private server
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) – common problems and fixes
- [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) – review findings, fixes and known limits
- [docs/PRODUCTION_CHECKLIST.md](docs/PRODUCTION_CHECKLIST.md) – go-live checklist
- [CHANGELOG.md](CHANGELOG.md) – version history
- [SECURITY.md](SECURITY.md) – how to report a vulnerability
- [LICENSE](LICENSE) – MIT
