# Security review

Review date: 2026-10-15 · Version 1.0.0 · Scope: every file under `src/`, the configuration schema, the deployment files and the dependency tree.

## Method

1. Every discord.js call was compiled against the installed discord.js 14.27.0 typings (`npm run typecheck`), so no invented method or option can exist in the production gateway.
2. Every specification scenario is covered by an automated test (123 tests, all passing).
3. Manual review of trust boundaries: Discord events, slash command input, button custom IDs, configuration file, environment, database content, Redis, files written to disk.
4. Static checks: no `eval`/`new Function` (the only `eval` is Redis' server-side Lua call for safe lock release), no string-built SQL (Kysely parameterizes everything; the only raw SQL is a constant `select 1`), no comments or console output in the codebase, no automatic ban anywhere.
5. Dependency audit: `npm audit` reports **0 vulnerabilities** (production and development) with pinned exact versions.
6. End-to-end run of the compiled CLI tools (check-config, migrate, backup, restore-test, verify-logs) and of the bot entrypoint up to the Discord login.

## Controls verified

| Area | Control |
| --- | --- |
| Supply chain | Exact versions, lockfile with integrity hashes, `ignore-scripts=true`, `engine-strict=true`, `npm audit` clean |
| Secrets | Token, HMAC key, database and Redis URLs only in environment variables; redaction in logger (paths and pattern scrubbing), evidence and alerts; webhook tokens never stored; `.env` and production config excluded from git |
| Input validation | zod schemas for environment and policy (strict objects, bounded numbers, snowflake format); slash options bounded by Discord and re-validated server-side; settings changed from Discord limited to a typed registry and re-validated against the schema, the semantic rules and the real server (role positions, permissions, bot or human, channel send permission); incident and snapshot IDs matched against strict patterns; button IDs matched against a strict pattern |
| Injection | Parameterized queries only; JSON stored as text; no regular expressions built from configuration (literal prefixes and domain suffix matching), input length caps on content analysis |
| Prototype pollution | Deep merge and path setter ignore `__proto__`, `constructor`, `prototype`; strict schemas drop nothing silently |
| Access control | Centralized in the router and the settings service; administrators and auditors changeable by the owner only; access re-checked on every panel interaction and at confirmation time; scope `all` approvals need the owner; self-approval refused; weakening changes need confirmation and, by default, the owner; panel sessions are ephemeral, bound to one user and one server, expire after 30 minutes of inactivity and are rate limited |
| Abuse of the bot | Per-user command rate limit; alert throttling for low severities; bounded in-memory maps (counters, recent messages, grant correlation, confirmations, detector samples) |
| Mentions | All outgoing messages use `allowedMentions: { parse: [] }` with explicit role or user allowlists; `@everyone`/`@here` neutralized in alert text |
| Double execution | Audit entries deduplicated by ID; incidents opened once per actor/category window; evidence appends serialized per server; lockdown serialized |
| Evidence integrity | Per-server HMAC-SHA256 chain with sequence numbers, constant-time hash comparison, anchors for retention, JSONL mirror, periodic verification with critical alert |
| Least privilege | No Administrator, no Ban Members; feature-level permission reporting; systemd sandbox with read-only code and no capabilities |
| Fail-safe | Database, Redis, alert channel and Discord API failures degrade features with alerts and fallback files; lockdown always expires; invites pause through Discord incident actions that expire on Discord's side |
| False positives | Monitor mode default; responses require automatic mode, policy and confidence; unknown authors never punished; legit-actor tests; owner and security admins never contained |

## Findings fixed during development

| # | Severity | Finding | Fix | Regression test |
| --- | --- | --- | --- | --- |
| 1 | High | A deduplication window keyed on (member, role) meant that an attacker re-granting a revoked Administrator role within ~30 seconds would not be evaluated | Deduplication is now keyed on the audit entry ID; the member-update fallback only skips grants already handled by the audit path after it was observed | `roleGuard.test.ts` › evaluates a re-grant performed right after a revocation |
| 2 | Medium | Links whose host was invalid punycode made `new URL` throw and were silently ignored | Unparseable links are reported as `malformed` (or `lookalike`) | `spam.test.ts` › classifies links by risk |
| 3 | Medium | Unicode homographs such as `dіscord.com` (Cyrillic і) were only rated as generic punycode | Hosts are decoded with `domainToUnicode`, normalized and mapped through a confusables table before look-alike detection | `spam.test.ts` › classifies links by risk |
| 4 | Low | Early startup failures could trigger a log-file flush before the async file stream was ready, producing a spurious unhandled rejection | The logger exposes a readiness promise awaited at startup; the entrypoint sets the exit code and lets streams drain | Manual end-to-end run |
| 5 | Low | Alert-message deletion could open two tamper incidents (audit path and bulk-delete path) | Single deduplication key per server | – |
| 6 | Low | The alert sanitizer broke Val Protection's own mention references in embeds (no security impact: embeds never ping) | Mention syntax kept, `@everyone`/`@here` still neutralized | – |
| 7 | Info | An invisible U+200B character was present in a source string literal | Replaced by an explicit `\u200b` escape; source scanned for other invisible characters | – |
| 8 | Medium | Installing from the lockfile with npm 10.9 ignored better-sqlite3's `gypfile: false` and forced a native rebuild (C/C++ toolchain and header download required; fails on Windows without Build Tools) | Project `.npmrc` with `ignore-scripts=true`: no dependency needs an install script, and dependency install scripts can no longer execute code during installation | Fresh `npm ci` from the lockfile, full test suite and build |
| 9 | Medium | Relying on Node's `--env-file` flag silently loaded nothing on Windows for `.env` files with carriage-return-only line endings (and on one Windows Node 24 setup even after normalization), so the bot started without secrets | Val Protection now loads `.env` itself: handles UTF-8/UTF-16/BOM, every line ending and invisible characters, never overrides non-empty system variables, never rewrites the file, and explains missing files, ignored lines and overridden keys | `tests/dotenv.test.ts` (7 tests) and an end-to-end run of the compiled bot with a CR-only file |
| 10 | Medium | Domain lists differing only by letter case were not deduplicated when edited from Discord | Domains are lower-cased before deduplication | `config.test.ts` › coerces values strictly |
| 11 | Info | Configuration moved from a host file to Discord (requested feature). Risk reviewed: a compromised Discord account could now reconfigure protections | Owner-only governance, weakening classification with confirmation and owner approval, full audit trail and announcements, server-side validation of every choice, read-only auditors, forged interactions refused | `settings.test.ts` (12 tests), `panel.test.ts` (10 tests) |

## Residual risks and known limits

| Risk | Rating | Notes and mitigation |
| --- | --- | --- |
| Reaction is after the fact | Inherent | Thresholds are low for destructive categories (3 channel deletions) and tighten during lockdown; snapshots allow structural recovery |
| Compromised owner account | Inherent | Alerts and fallback webhook only; enable 2FA for the owner |
| Actors above Val Protection's role | High if misconfigured | Scanner and startup checks report it; place the bot role high |
| Administrator escalation on a role cannot be reverted without Administrator | Medium | Critical incident, actor restricted; requires manual fix. Granting the bot Administrator would remove this limit but increases the blast radius of a token leak; this trade-off is intentionally left to the operator |
| Host compromise with the HMAC key | High | The chain can be rewritten; keep the key out of backups, harden the VPS, ship `evidence.jsonl` off the host |
| Truncation of the newest evidence records directly in the database | Medium | Detectable by comparing with the JSONL mirror and the alerts already posted; ship the mirror to remote storage |
| Missing audit entries | Medium | Unattributed incidents need human review by design |
| Very slow raids with aged accounts | Medium | Look like organic growth; Discord verification levels and AutoMod complement Val Protection |
| Single process without Redis | Low | Counters reset on restart (lockdowns persist); use Redis for multi-instance deployments |
| No sharding | Low | Suitable for a private bot on a limited number of servers; very large deployments need discord.js sharding |
| Heuristic spam detection | Low | Conservative thresholds, warning first, no kicks or bans |

## Recommendations for operators

1. Keep `mode: monitor` until `/security scan` is clean and thresholds are tuned.
2. Keep Public Bot disabled and set `allowedGuildIds`.
3. Enable 2FA requirement for moderation and 2FA on every administrator account.
4. Store `EVIDENCE_HMAC_KEY` in a password manager, separate from backups.
5. Ship `evidence.jsonl` and backups to remote encrypted storage.
6. Run `npm run audit:deps` and review updates monthly.
7. Rotate the bot token immediately if it may have leaked.
