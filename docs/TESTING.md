# Testing

## Automated tests

```bash
npm test
npm run typecheck
```

The suite never contacts Discord. It uses:

- `InMemoryGateway` (`src/simulation/inMemoryGateway.ts`): a complete fake of the gateway port that applies role, permission, hierarchy and membership changes in memory, records every call, and can simulate failures of one method or of the whole API;
- an in-memory SQLite database with the real migrations;
- `FakeClock`, so windows, cooldowns, expiries and correlation delays run instantly and deterministically.

| Specification scenario | Test |
| --- | --- |
| Simulated raid | `antiRaid.test.ts` › detects a raid, locks down and quarantines suspects without banning |
| Wave of suspicious accounts | `antiRaid.test.ts` › detects a slow wave of suspicious accounts |
| Mass ban | `antiNuke.test.ts` › contains a mass ban by removing only the role granting Ban Members |
| Mass kick | `antiNuke.test.ts` › contains a mass kick |
| Forbidden Administrator grant | `roleGuard.test.ts` › revokes the role from the recipient and removes only the granter's role-management access |
| Protected role permission change | `roleGuard.test.ts` › reverts only the dangerous permissions…, is honest when Discord prevents reverting Administrator |
| Unapproved bot | `botsAndIntegrations.test.ts` › unapproved bots |
| Mass channel deletion | `antiNuke.test.ts` › detects mass channel deletion, contains it and offers recovery |
| Database failure | `resilience.test.ts` › keeps protecting, alerting and records evidence in the fallback file |
| Discord API unavailable | `resilience.test.ts` › Discord API unavailability |
| Invalid input | `config.test.ts` › configuration file, environment, runtime settings and invalid input |
| Legitimate admin action | `roleGuard.test.ts` › leaves a grant made by a configured security administrator untouched |
| Grant with unknown author | `roleGuard.test.ts` › alerts but never revokes automatically when the granter cannot be identified |
| Configuration from Discord | `settings.test.ts` (owner-only governance, weakening rules, validation against the server, protected roles, granters, whitelist, concurrency) and `panel.test.ts` (every view rendered within Discord limits for owner, security admin and auditor; full click-through flows; confirmation and cancel; forged and expired interactions) |

Additional coverage: false-positive checks (normal joins, normal conversation, actions spread over time), regrant bypass, lockdown persistence and restoration, `.env` loading on Windows (encodings, line endings, invisible characters, precedence), evidence tampering, deletion and forgery detection, retention anchors, secret redaction, link analysis including Unicode homographs, honeypot correlation, scanner findings, recovery with remapped overwrites, confirmation binding, command definition consistency and the full rule simulation.

## In-Discord simulation

`/security test` runs the same scenarios as `src/simulation/ruleTester.ts` against your server's **current thresholds** on a synthetic in-memory server (mode forced to automatic so you can see the complete response). Nothing is sent to Discord except the result.

## Manual validation on a private test server

Never test on a production server. Create a server you own, invite a separate test application, and use test accounts.

| Scenario | Steps | Expected |
| --- | --- | --- |
| Panel setup | As the owner, run `/security panel`, choose the alert channel, security admins and quarantine role, send a test alert | Each change is confirmed in the panel and announced in the alert channel; the setup checklist empties |
| Panel limits | As a security admin, try to turn anti-raid off; as an auditor, open the panel | Refused with the reason and announced; auditor sees a read-only panel |
| Monitor mode | Keep monitor mode, perform every scenario below | Alerts and evidence only, no change on the server |
| Unauthorized admin grant | Give a test moderator Manage Roles only, have them give an Administrator role to another account | Alert; in automatic mode the role is removed and the moderator loses only the Manage Roles role |
| Authorized grant | Add your account as a security administrator in the panel, grant the same role | Evidence `role.grant.authorized`, no action |
| Mass ban | Have the moderator ban 4 test accounts within a minute | Incident `nuke.memberBan`, Ban Members role removed, lockdown |
| Mass channel deletion | Delete 3 test channels within a minute | Incident, containment, `/security backup-status` shows them missing, `/security recover` recreates them |
| Raid | Join several fresh test accounts quickly (respect Discord's Terms of Service; do not use automation against Discord) or rely on `/security test` | Incident, lockdown, quarantine role applied |
| Spam | Post the same message repeatedly | Warning, deletion, timeout |
| Unapproved bot | Invite any harmless bot | Pending review incident |
| Webhook | Create a webhook with an unauthorized account | Incident; deleted when configured |
| Tampering | Delete an alert message, remove a permission from Val Protection's role | Tamper incidents |
| Unlock | `/security unlock`, confirm | Verification level and invites restored |
| Restart | Restart the bot during a lockdown | Lockdown still active, expires on time |

After each session run `/security logs source:verify` and `npm run verify-logs`.
