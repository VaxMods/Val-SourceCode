# Configuration reference

**Normal use: configure each server with `/security panel` in Discord.** Every per-server key below marked *panel* is edited there with role, channel and member pickers, toggles and forms. The panel stores its choices in the database, per server.

The JSON file (`CONFIG_PATH`, default `./config/val-protection.json`) is **optional**. Without it, built-in defaults apply. Use it only for process-wide settings (`global`), for advanced tuning keys that the panel does not expose (marked *file*), or to pre-seed defaults for several servers. Start from `config/val-protection.example.json`, which is generated from the schema defaults.

```json
{
  "version": 1,
  "global": { "...": "process-wide settings" },
  "defaults": { "...": "policy applied to every server" },
  "guilds": { "<server id>": { "...": "overrides for that server" } }
}
```

Layers, from lowest to highest priority: built-in defaults, `defaults` from the file, `guilds.<id>` from the file, then the choices made in `/security panel` (or `/security config`). Objects merge, lists replace.

Validation happens at startup and on every change made from Discord:

- **Schema**: unknown keys are rejected (typos never pass silently), IDs must be Discord snowflakes, numbers have bounds.
- **Semantic errors** (startup refused): kicking suspects outside a confirmed raid, a decoy role used as quarantine or protected role or staff role, the alert channel used as a decoy channel, `dangerousPermissions` without Administrator, a domain both allowed and blocked, all raid weights at zero.
- **Warnings** (startup continues, listed in logs and in the "online" alert): no alert channel in automatic mode, no security admin, quarantine selected without a quarantine role, thresholds that trigger on every action, low raid thresholds, `VeryHigh` lockdown verification, `revokeWhenActorUnknown`.
- **File permissions**: a world-writable configuration file is refused on Linux.

`npm run check-config` runs the same validation without starting the bot.

## global

| Key | Default | Description |
| --- | --- | --- |
| `allowedGuildIds` | `[]` | If not empty, Val Protection ignores every other server (events and commands) |
| `commandRateLimit.limit` / `.windowSeconds` | `6` / `30` | Maximum `/security` invocations per user per window |
| `schedulerTickSeconds` | `15` | Frequency of expiry, cooldown and restoration checks |
| `integrityCheckIntervalMinutes` | `360` | Evidence chain verification frequency |
| `maxMembersForFullScan` | `25000` | Above this member count, `/security scan` skips member-level checks |

## Top level

| Key | Default | Description | Where |
| --- | --- | --- | --- |
| `mode` | `monitor` | `monitor` alerts and records only; `automatic` also responds | panel (switching to monitor is a weakening change) |
| `alertChannelId` | `null` | Private channel for alerts; Val Protection must be able to post in it | panel (moving or removing it is a weakening change) |
| `alertPingRoleId` | `null` | Role pinged for high and critical alerts | panel |
| `securityAdminIds` | `[]` | Users allowed to administer Val Protection | panel, **owner only** |
| `auditorRoleIds` | `[]` | Roles allowed to read status, logs, incidents and the panel | panel, **owner only** |
| `staffRoleIds` | `[]` | Staff roles: exempt from anti-spam, never timed out by the honeypot, their channel overwrites are not reported | panel (adding is a weakening change) |
| `weakeningChangesRequireOwner` | `true` | Changes that weaken protection need the server owner | panel, **owner only** |

## antiRaid

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable the anti-raid engine |
| `windowSeconds` | `30` | Surge detection window |
| `minJoinsForRaid` | `8` | Minimum joins in the window to consider a surge |
| `slowWaveWindowMinutes` | `15` | Window for slow waves |
| `slowWaveSuspectCount` | `6` | Suspicious joins in the slow window that trigger an incident |
| `adaptive.enabled` | `true` | Learn the normal join rate |
| `adaptive.halfLifeMinutes` | `60` | Half-life of the learned baseline |
| `adaptive.multiplier` | `4` | Threshold = max(minJoinsForRaid, baseline × multiplier) |
| `adaptive.maxGrowthPerBucket` | `1.25` | Maximum baseline growth per window, so attackers cannot ramp it up quickly; the baseline is frozen during raids and lockdowns |
| `raidScoreThreshold` | `60` | Raid score (rate 50 + suspicious ratio 30 + clusters 20) needed with the join threshold |
| `suspectScoreThreshold` | `60` | Member risk score considered suspicious |
| `newAccountDays` | `7` | Accounts younger than this get age points (linear) |
| `weights.*` | 35/10/25/20/25/40 | Points for accountAge, noAvatar, usernameCluster, creationCluster, rejoinAfterAction, spammerFlag |
| `suspectAction` | `quarantine` | `none`, `quarantine`, `timeout` or `kick` |
| `actOnlyDuringRaid` | `true` | Apply measures only during a raid or lockdown (`kick` requires `true`) |
| `quarantineRoleId` | `null` | Role without permissions used for quarantine |
| `timeoutMinutes` | `60` | Timeout duration when `suspectAction` is `timeout` |
| `kickMinScore` | `90` | Minimum score for a kick; lower scores are downgraded to quarantine or timeout |
| `autoLockdown` | `true` | Start lockdown when a raid is detected (automatic mode) |
| `raidCooldownMinutes` | `5` | Minutes without signal before a raid is considered over |

## antiNuke

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable the engine |
| `response` | `contain` | `alert` only, or `contain` the actor |
| `minConfidenceToContain` | `high` | `high` (live audit entry) or `medium` (fetched entry) |
| `containBotsByKick` | `true` | Kick a bot that crosses a threshold |
| `autoLockdownOnSeverity` | `critical` | `never`, `high` or `critical` |
| `lockdownThresholdFactor` | `0.5` | Thresholds are multiplied by this during lockdown |
| `unattributedSpikeFactor` | `2` | Multiplier for spikes without an author (alert only) |
| `thresholds.<category>.limit` / `.windowSeconds` | see below | Per-actor limits |

| Category | Default | Category | Default |
| --- | --- | --- | --- |
| channelCreate | 6 / 60s | memberRoleUpdate | 20 / 60s |
| channelDelete | 3 / 60s | webhookCreate | 3 / 300s |
| channelUpdate | 10 / 60s | webhookUpdate | 6 / 300s |
| overwriteUpdate | 12 / 60s | webhookDelete | 3 / 300s |
| roleCreate | 5 / 60s | botAdd | 2 / 600s |
| roleDelete | 3 / 60s | integrationCreate | 2 / 600s |
| roleUpdate | 6 / 60s | integrationUpdate | 4 / 600s |
| memberBan | 4 / 60s | integrationDelete | 2 / 600s |
| memberKick | 5 / 60s | guildUpdate | 4 / 300s |
| memberPrune | 1 / 3600s | commandPermissionUpdate | 3 / 600s |

The owner and security administrators are never contained (alerts still fire). Whitelisted actors for the matching scope are logged and only reported above three times the limit.

## roleProtection

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable role protection |
| `treatDangerousRolesAsProtected` | `true` | Any role carrying a dangerous permission is protected |
| `dangerousPermissions` | Administrator, ManageGuild, ManageRoles, ManageWebhooks, BanMembers, KickMembers, ManageChannels, ModerateMembers, MentionEveryone | Must include Administrator |
| `protectedRoleIds` | `[]` | Roles always protected (cannot be unprotected from Discord) |
| `authorizedGranterIds` | `[]` | Users allowed to grant every protected role |
| `revokeFromRecipient` | `true` | Revoke unauthorized grants |
| `granterResponse` | `strip-role-management` | `none`, or remove the granter's roles that grant Manage Roles/Administrator (high confidence only) |
| `minConfidenceToRevoke` | `high` | Minimum confidence to revoke from the recipient |
| `revokeWhenActorUnknown` | `false` | Revoke even when the granter is unknown (not recommended) |
| `revertUnauthorizedPermissionChanges` | `true` | Remove newly added dangerous permissions from roles |
| `correlationDelayMs` | `2500` | Wait before the fallback attribution of a member update |
| `correlationWindowSeconds` | `15` | Age limit of audit entries used for fallback attribution |

Per-role granters are managed with `/security protect-role` (stored in the database, merged with the file list).

## bots

| Key | Default | Description |
| --- | --- | --- |
| `approvedBotIds` | `[]` | Bots approved in the file |
| `authorizedAdderIds` | `[]` | Users allowed to add bots |
| `unapprovedAction` | `alert` | `alert` or `kick` |
| `kickOnlyWhenAdderUnauthorized` | `true` | With `kick`, only kick when the adder is unauthorized and identified with high confidence |

## integrations

| Key | Default | Description |
| --- | --- | --- |
| `authorizedManagerIds` | `[]` | Users allowed to manage webhooks and integrations |
| `unauthorizedWebhookAction` | `alert` | `alert` or `delete` |

## antiSpam

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable anti-spam |
| `burst.maxMessages` / `.windowSeconds` | `7` / `6` | Burst limit per user |
| `duplicates.max` / `.windowSeconds` | `4` / `30` | Same normalized content (any channel) |
| `maxMentions` | `6` | User and role mentions per message |
| `caps.ratio` / `.minLength` | `0.8` / `20` | Capital letters ratio for messages with at least `minLength` letters |
| `maxRepeatedChars` | `25` | Longest run of one character (combining-mark floods are also detected) |
| `links.blockedDomains` / `allowedDomains` | `[]` | Domains or `*.domain` wildcards; allowed wins over every other heuristic |
| `links.flagInvites`, `flagShorteners`, `flagLookalikes`, `flagIpHosts` | `true` | Heuristics; punycode and malformed URLs are always reported |
| `threads.max` / `.windowSeconds` | `3` / `300` | Thread creation per user |
| `strikeDecaySeconds` | `600` | Strikes expire after this window |
| `timeoutMinutes` | `10` | Timeout at the last ladder level |
| `warnCooldownSeconds` | `30` | Minimum time between warnings to the same user |
| `exemptRoleIds`, `exemptChannelIds` | `[]` | Exemptions (members with Manage Messages and staff roles are always exempt) |
| `floodSlowmode.*` | enabled, 5 users, 15s, 10s slowmode, 10 min | Temporary slowmode when several users flood one channel |

Ladder: 1–2 strikes warn, 3–4 delete + warn, 5+ timeout and staff alert. High-risk links and mass mentions are deleted immediately.

## honeypot

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable traps |
| `decoyRoleIds` | `[]` | Roles without permissions used as bait |
| `decoyChannelIds` | `[]` | Channels where non-staff messages are signals |
| `forbiddenCommandPatterns` | `!nuke`, `!massban`, `!banall`, `!kickall`, `!raid`, `.nuke` | Literal prefixes (no regular expressions) |
| `correlationWindowMinutes` | `60` | Correlation window |
| `escalationScore` | `4` | Score that turns signals into an incident |
| `escalationAction` | `alert` | `alert` or `timeout` (never staff or security admins) |
| `timeoutMinutes` | `60` | Escalation timeout |

Signal weights: unauthorized command 1, forbidden command 1, decoy channel message 1, foreign confirmation 2, decoy role granted 2, decoy role given permissions 3.

## lockdown

| Key | Default | Description |
| --- | --- | --- |
| `maxDurationMinutes` | `120` | Hard cap (5–1440) |
| `raiseVerificationLevel` | `true` | Raise the server verification level |
| `verificationLevel` | `High` | `Medium`, `High` or `VeryHigh` |
| `pauseInvites` | `true` | Pause invites until the lockdown ends |
| `quarantineNewMembers` | `true` | Quarantine every new member during lockdown (requires a quarantine role) |
| `restrictProtectedRoleGrants` | `true` | Only the owner and security admins may grant sensitive roles |
| `suspendNonEssential` | `true` | Suspend non-essential bot messages (spam warnings) during lockdown |

## backups

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Structural snapshots |
| `intervalMinutes` | `360` | Snapshot frequency (skipped during lockdown so damage is not captured) |
| `keep` | `14` | Snapshots kept per server |

## logging

| Key | Default | Description |
| --- | --- | --- |
| `retentionDays` | `180` | Evidence retention (minimum 30). Lowering it at runtime is a weakening change |

## What the panel edits

Every per-server key in this document is editable in `/security panel`, except these advanced tuning keys, which stay in the optional file:

| Section | File-only keys |
| --- | --- |
| antiRaid | `weights.*`, `adaptive.*` |
| antiNuke | `lockdownThresholdFactor`, `unattributedSpikeFactor` |
| roleProtection | `dangerousPermissions`, `minConfidenceToRevoke`, `revokeWhenActorUnknown`, `correlationDelayMs`, `correlationWindowSeconds` |
| antiSpam | `caps.*`, `maxRepeatedChars`, `threads.*`, `strikeDecaySeconds`, `warnCooldownSeconds`, `duplicates.windowSeconds`, `floodSlowmode` numbers |
| honeypot | `correlationWindowMinutes`, `escalationScore`, `timeoutMinutes` |
| global | every key |

`/security config key:<setting> value:<value>` changes one scalar setting directly (the key option autocompletes); lists are edited in the panel.

## Weakening changes

A change **weakens** protection when it turns a protection or a lockdown action off, switches to monitor mode or to a less strict response, raises a limit or shortens a detection window, lowers retention, adds someone to a trusted list (staff roles, exempt roles and channels, allowed granters, approved bots, allowed bot adders, webhook managers, allowed domains, whitelist), removes something from a protective list (protected roles, decoy roles and channels, blocked domains, forbidden command traps), or moves or removes the alert channel.

Weakening changes always ask for a confirmation click, are announced with high severity ("Protection weakened"), and require the server owner while `weakeningChangesRequireOwner` is on. Owner-only settings (`securityAdminIds`, `auditorRoleIds`, `weakeningChangesRequireOwner`, whitelist scope `all`) also ask for confirmation. Refused attempts are recorded and announced.
