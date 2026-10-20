# Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Val Protection failed to start: Invalid environment configuration` | Missing or malformed variable | The message lists every variable; compare with `.env.example` |
| `No .env file found at …` | Command run from another folder, or the file is named `.env.txt` | Run commands from the project folder; on Windows check with `dir /a .env*` and rename with `ren .env.txt .env` |
| `Already defined in the system environment, so the system value wins: …` | The same variable exists in Windows or shell environment variables (often left by another bot project) | Remove it from the system environment variables (`rundll32 sysdm.cpl,EditEnvironmentVariables` on Windows), then reopen the terminal |
| `.env lines ignored because they are not KEY=value` | A line without `=` or with an invalid name | Fix the listed line numbers |
| `EVIDENCE_HMAC_KEY must decode to at least 32 bytes` | Key too short | Generate one with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| Log line `No configuration file: built-in defaults apply` | Normal: the file is optional | Configure the server with `/security panel` |
| `/security panel` does not exist | Commands not redeployed after the update | `npm run deploy-commands` (or `deploy-commands:global`) |
| Panel says "This panel expired or was replaced" | 30 minutes without activity, a newer panel opened, or the bot restarted | Run `/security panel` again |
| Panel refuses a change with "require the server owner" | The change weakens protection and *Owner approval for weakening changes* is on | Ask the owner, or the owner turns that option off in General |
| Panel refuses a role or channel | The choice fails a safety check (role above Val Protection, decoy with permissions, channel Val Protection cannot post in…) | Fix the role position or permissions as the message says |
| `Invalid configuration file … Unrecognized key` | Typo in a key | Fix the key; unknown keys are refused on purpose |
| `world-writable` | Unsafe file mode | `chmod 640` the file |
| `Pending database migrations` | `MIGRATE_ON_START=false` after an update | `npm run migrate` |
| `Used disallowed intents` or disconnect code 4014 | Privileged intents disabled | Enable Server Members and Message Content intents in the Developer Portal |
| Login fails with `TokenInvalid` or 401 | Token revoked or wrong | Reset the token and update the environment |
| `getaddrinfo ENOTFOUND discord.com` | No DNS or outbound network | Check the firewall, proxy and DNS of the host |
| `/security` does not appear | Command not registered or hidden | `npm run deploy-commands` (guild) or `deploy-commands:global` (up to one hour); check Server Settings → Integrations; the command requires Manage Server visibility by default |
| "This command requires the auditor/security admin access level" | Not listed in the policy | Add your user ID to `securityAdminIds` (file) or give an `auditorRoleIds` role; Discord Administrator alone is not enough by design |
| Startup alert lists "feature disabled (missing …)" | Missing bot permission | Grant the listed permission to Val Protection's role |
| "role is at or above Val Protection's highest role" | Hierarchy | Move Val Protection's role above the roles it must manage |
| "Discord only lets a bot add or remove permissions it holds itself" | Reverting a permission the bot lacks (typically Administrator) | Fix the role manually; the actor was still restricted when possible |
| Grants reported as "granter could not be identified" | Missing View Audit Log, missing Guild Moderation intent, or Discord did not create an entry | Check permissions and intents; review manually |
| No alert in the alert channel | Channel deleted, permissions missing, or throttling | Check `alerts-fallback.jsonl`, the fallback webhook, and `/security status`; lower-severity alerts above 20 per minute are summarized |
| `Evidence chain BROKEN` | Database modified outside Val Protection, restored from an inconsistent copy, or wrong HMAC key | Preserve the database and `evidence.jsonl`; compare records around the reported sequence; verify the key |
| `Evidence store unavailable; writing to fallback file` | Database unreachable or disk full | Fix the database; records written during the outage are in `evidence-fallback.jsonl` |
| Redis errors at startup | Redis unreachable or wrong password | Fix Redis or remove `REDIS_URL` |
| `Could not locate the bindings file` for better-sqlite3 | Platform without a bundled prebuilt binary | Install build tools (`build-essential` / Visual Studio Build Tools) and run `npm rebuild better-sqlite3 --ignore-scripts=false` |
| `npm ci` tries to run `node-gyp rebuild` | The project `.npmrc` was not copied | Keep `.npmrc` (it sets `ignore-scripts=true`) |
| Too many raid incidents on a busy server | Thresholds too low for normal traffic | Raise `minJoinsForRaid` or `raidScoreThreshold`, keep `adaptive.enabled`; validate with `/security test` |
| Legitimate moderation flagged as nuke | Large planned cleanup | Add a time-limited whitelist entry for the moderator and scope (`/security whitelist add … hours:2`) before the operation |
| Lockdown did not resume invites | Invites paused with the feature-flag fallback and the bot lacked permission at unlock | Re-enable invites in Server Settings; check Manage Server |
| Bot keeps running after Ctrl+C on Windows | Console signal not forwarded by a wrapper | Stop the service through NSSM; it sends Ctrl+C and waits |

Useful commands:

```bash
journalctl -u val-protection -n 100
npm run check-config
npm run verify-logs
npm run restore-test
```
