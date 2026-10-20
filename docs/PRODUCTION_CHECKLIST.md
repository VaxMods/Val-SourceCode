# Production checklist

## Discord application

- [ ] Application created; **Public Bot disabled**
- [ ] Token stored only in the environment file (mode 640/600), never committed
- [ ] Server Members and Message Content intents enabled; Presence disabled
- [ ] Invited with `bot applications.commands` and permission integer `1100317060274` (no Administrator, no Ban Members)
- [ ] `/security` registered (`npm run deploy-commands:global` or guild deployment)

## Server

- [ ] Val Protection's role placed above every role it must protect
- [ ] Private alert channel created (chosen later in `/security panel`)
- [ ] Quarantine role without permissions, denied on public channels, below the bot (chosen later in `/security panel`)
- [ ] Decoy roles/channels (optional) without any permission
- [ ] Owner enabled "Require 2FA for moderator actions"; all administrators use 2FA
- [ ] Discord AutoMod configured as a complement
- [ ] `/security scan` shows no critical or high finding left unexplained

## Configuration

- [ ] `npm run check-config` passes (no configuration file is needed; if you use one, keep it mode 640 and owned by root)
- [ ] `EVIDENCE_HMAC_KEY` generated (32+ random bytes) and stored in a password manager
- [ ] `ALERT_FALLBACK_WEBHOOK_URL` points to a channel in another server
- [ ] `allowedGuildIds` set in the configuration file if the instance must ignore unexpected servers
- [ ] `/security panel` → General: alert channel chosen, test alert received
- [ ] `/security panel` → Access: security administrators and auditor roles reviewed by the owner; staff roles reviewed
- [ ] `/security panel` → Anti-raid: quarantine role chosen
- [ ] *Owner approval for weakening changes* left on unless you have a reason to turn it off
- [ ] Setup checklist on the panel home screen is empty
- [ ] Started in monitor mode, observed for several days, thresholds tuned
- [ ] `/security test` passes with the final thresholds
- [ ] Mode switched to automatic deliberately, by the owner

## Host

- [ ] Node.js 22.12+ installed from a trusted source
- [ ] Dedicated `valprotection` user, code read-only, data/log/backup directories 700
- [ ] systemd service enabled with sandboxing; `systemctl status` healthy
- [ ] Firewall: no inbound port except SSH; SSH key-only
- [ ] Automatic security updates enabled
- [ ] Log rotation installed and tested (`logrotate --debug`)
- [ ] PostgreSQL (if used) with a dedicated role, strong password, TLS for remote access
- [ ] Redis (if used) bound to localhost with a password

## Backups and evidence

- [ ] Backup timer enabled; first backup created
- [ ] `npm run restore-test` passes
- [ ] Backups and `evidence.jsonl` copied off the host, encrypted
- [ ] `npm run verify-logs` passes
- [ ] Retention (`logging.retentionDays`) matches your policy

## Validation on a private test server

- [ ] Unauthorized Administrator grant revoked and granter restricted
- [ ] Authorized grant untouched
- [ ] Mass ban contained
- [ ] Lockdown activates, expires, and `/security unlock` restores settings
- [ ] Alert channel deletion falls back to the webhook
- [ ] Restart during lockdown keeps the lockdown

## Operations

- [ ] On-call people know `/security status`, `/security lockdown`, `/security incident`, `/security unlock`
- [ ] Incident procedure documented: contain (lockdown), identify (incident, evidence), secure accounts (password, 2FA, sessions), recover (`/security recover`), review (logs, verify-logs)
- [ ] Monthly: `npm run audit:deps`, dependency review, restore test, scan review
