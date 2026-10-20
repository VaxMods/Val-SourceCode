# Discord API limits and how Val Protection handles them

This document lists, feature by feature, what the Discord API and discord.js 14.27.0 actually allow, and what Val Protection does about each limit. Every method used by the code was verified against the installed discord.js type definitions; the production gateway (`src/discord/discordGateway.ts`) compiles against them.

## General limits

| Limit | Consequence | What Val Protection does |
| --- | --- | --- |
| No pre-action hooks | No bot can block a ban, deletion or role change before Discord executes it | Reacts on the gateway event (usually within a second) and documents the delay |
| Server owner is above everything | No bot can restrict, time out, kick or demote the owner | Alerts with a recommendation to secure the owner account; never attempts an action against the owner |
| Role hierarchy | A bot can only manage roles strictly below its highest role and members whose highest role is below it | Checks hierarchy before acting; reports "manual intervention required" with the reason; the scanner lists sensitive roles above the bot |
| Permission ownership | A bot cannot add or remove a permission it does not hold, in roles or channel overwrites, and cannot create roles with permissions it lacks | Checks the changed bits against its own permissions before editing; recovery drops unrestorable permissions and lists them |
| Administrator cannot be timed out | Timeouts fail on members with Administrator | Checked before calling; reported as skipped |
| Rate limits | Bulk responses are throttled | discord.js queues and retries requests; responses are proportional (one role removal per abuser, not per event); rate-limit events are logged |
| Gateway delivery is best effort | Events can arrive late, out of order, or be missed during reconnects | Audit events are deduplicated; member updates are correlated with a delay and a fallback audit-log fetch; startup verification re-checks configuration |

## Audit log

| Fact | Handling |
| --- | --- |
| `GUILD_AUDIT_LOG_ENTRY_CREATE` requires the **Guild Moderation** intent and the **View Audit Log** permission | Both are documented and checked; without them attribution is unavailable and confidence drops to none |
| Not every action produces an entry (voluntary leaves, some automatic Discord actions, onboarding) | Grants without an entry are reported as unattributed; no automatic revocation unless `revokeWhenActorUnknown` is explicitly enabled |
| Entries can be grouped or arrive after the gateway change | Member role updates wait `correlationDelayMs`, then search the latest entries within `correlationWindowSeconds`; ambiguous matches get low confidence |
| Role position changes do not create audit entries | Hierarchy changes come from `guildRoleUpdate` without an author (medium confidence, alert only) |
| Bulk ban entries can differ from single bans | Ban events are also counted without attribution; a spike raises a "needs review" incident without action |
| Entries are kept by Discord for 45 days | Val Protection keeps its own evidence chain with configurable retention (minimum 30 days) |

Confidence levels used everywhere:

| Confidence | Meaning |
| --- | --- |
| high | Live audit entry with an executor, or a fetched entry that is the only candidate for that target and role |
| medium | Fetched audit entry used for thresholds (not live) |
| low | Several candidate entries with different executors, or attribution inferred from aggregate events |
| none | No author available |

## Raids

| Possible | Not possible |
| --- | --- |
| Account creation date (from the snowflake), default avatar, username, Discord spammer flag (`UserFlags.Spammer`, unofficial and best effort) | Knowing which invite a member used without racy invite diffing (not implemented), IP or device information, verified email/phone status of other users |
| Raising the verification level (`Guild#setVerificationLevel`, Manage Server) | Enforcing a custom captcha inside Discord (would require a separate verification flow) |
| Pausing invites with incident actions (`Guild#setIncidentActions`, `invitesDisabledUntil`, maximum 24 hours, expires on Discord's side) with a fallback to the `INVITES_DISABLED` feature (`Guild#disableInvites`) which does **not** expire by itself | Blocking joins through vanity URLs or other bots' invite systems beyond what Discord's invite pause covers |
| Quarantine role, timeouts (maximum 28 days), kicks | Banning is possible but deliberately never used automatically |

## Destructive actions (nuke)

| Possible | Not possible |
| --- | --- |
| Detecting deletions, creations and updates of channels, roles, webhooks, overwrites, bans, kicks, prunes, bots, integrations, server settings through audit entries | Undeleting a channel, role, message, webhook or emoji |
| Removing the roles that grant the abused permission from the actor | Restricting the owner; removing a permission granted by @everyone without editing @everyone |
| Kicking a bot that performs destructive actions | Stopping an action already queued by Discord |
| Recreating roles and channels from a snapshot (new IDs, limited to permissions the bot holds) | Restoring messages, threads, pins, invites, webhooks, integrations or member role assignments |

## Roles and permissions

| Possible | Not possible |
| --- | --- |
| Reading effective member permissions and role permissions | Seeing why Discord granted a role through onboarding, linked roles or another bot beyond the audit executor |
| Removing a role from a member below the bot | Removing a managed integration role from its bot |
| Reverting newly added permissions the bot holds itself | Reverting Administrator without holding Administrator |
| Detecting position changes | Attributing position changes to an author |

## Bots and integrations

| Possible | Not possible |
| --- | --- |
| Detecting bot additions with the adder (`BOT_ADD` entry) | Preventing a bot from joining; reviewing its code or intentions |
| Kicking a bot below Val Protection | Kicking a bot whose role is above Val Protection |
| Deleting a webhook with Manage Webhooks | Restoring a deleted webhook or its URL |
| Detecting command permission updates (`APPLICATION_COMMAND_PERMISSION_UPDATE`) | Preventing administrators from changing command visibility in Server Settings |

## Messages and spam

| Possible | Not possible |
| --- | --- |
| Reading content with the privileged Message Content intent | Reading content without the intent |
| Deleting messages (single or bulk; bulk only for messages younger than 14 days) | Deleting messages older than 14 days in bulk |
| Channel slowmode (per channel, not per user) | Per-user slowmode |
| Timeouts | Shadow-muting |

Discord's native AutoMod complements Val Protection and runs before messages are posted. Using both is recommended.

## Lockdown

Lockdown only uses settings Discord allows a bot to change: verification level and invite pause, plus Val Protection's own behaviour (quarantine of new members, stricter thresholds, owner-or-security-admin-only sensitive grants, suspended non-essential messages). It never edits channel overwrites in bulk and never touches administrator roles, so administrators keep every capability needed to recover. It always has an expiry (maximum 24 hours) and can be ended early by `/security unlock`.

## Commands

`/security` uses `setDefaultMemberPermissions(ManageGuild)` and `setContexts(Guild)`. Server administrators can change command visibility in Server Settings → Integrations; Val Protection therefore applies its own access control on every invocation and reports visibility changes as tampering.
