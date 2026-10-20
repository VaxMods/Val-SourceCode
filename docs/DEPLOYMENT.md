# Deployment

This guide deploys Val Protection on an Ubuntu 24.04 VPS with systemd, a dedicated system user, filesystem sandboxing, log rotation and daily tested backups. Adapt package commands for other distributions.

## 1. Prepare the server

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y git build-essential ufw unattended-upgrades
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw enable
sudo dpkg-reconfigure -plow unattended-upgrades
```

Val Protection needs **no inbound port**: it only opens outbound HTTPS/WebSocket connections to Discord.

Harden SSH (key-only login, no root login) before going further.

## 2. Install Node.js 22 LTS

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v
```

## 3. Create the service user and directories

```bash
sudo useradd --system --home /opt/val-protection --shell /usr/sbin/nologin valprotection
sudo mkdir -p /opt/val-protection /etc/val-protection /var/lib/val-protection /var/log/val-protection /var/backups/val-protection
sudo chown valprotection:valprotection /var/lib/val-protection /var/log/val-protection /var/backups/val-protection
sudo chmod 700 /var/lib/val-protection /var/log/val-protection /var/backups/val-protection
```

## 4. Install the application

```bash
sudo git clone https://github.com/Vax-Bex/Val-SourceCode.git /opt/val-protection
cd /opt/val-protection
sudo npm ci
sudo npm run build
sudo npm test
sudo npm prune --omit=dev
sudo chown -R root:root /opt/val-protection
```

The code stays owned by root and read-only for the service user, so a compromised process cannot modify itself.

## 5. Secrets and configuration

```bash
sudo cp deploy/val-protection.env.example /etc/val-protection/val-protection.env
sudo cp config/val-protection.example.json /etc/val-protection/val-protection.json
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
sudo nano /etc/val-protection/val-protection.env
sudo nano /etc/val-protection/val-protection.json
sudo chown root:valprotection /etc/val-protection/val-protection.env /etc/val-protection/val-protection.json
sudo chmod 640 /etc/val-protection/val-protection.env /etc/val-protection/val-protection.json
```

The configuration file is optional: every per-server setting is configured in Discord with `/security panel`. Keep the file only for `allowedGuildIds` and advanced tuning; otherwise skip the copy and the `val-protection.json` lines above.

Store a copy of `EVIDENCE_HMAC_KEY` in your password manager, **not** next to the database backups. Without it the evidence chain cannot be verified; with it anyone can forge evidence.

Validate:

```bash
sudo -u valprotection ENV_FILE=/etc/val-protection/val-protection.env node /opt/val-protection/dist/cli/checkConfig.js
```

## 6. Register the slash command

```bash
sudo -u valprotection ENV_FILE=/etc/val-protection/val-protection.env node /opt/val-protection/dist/cli/deployCommands.js --global
```

## 7. systemd service

```bash
sudo cp deploy/val-protection.service /etc/systemd/system/
sudo cp deploy/val-protection-backup.service deploy/val-protection-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now val-protection.service
sudo systemctl enable --now val-protection-backup.timer
sudo systemctl status val-protection
journalctl -u val-protection -f
```

The unit runs `check-config` before every start, restarts on failure, sends `SIGTERM` for a graceful shutdown (in-flight handlers are drained, then Discord, Redis and the database are closed), reopens the log file on `systemctl reload`, and applies systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, no capabilities, private `/tmp`, only the data, log and backup directories writable).

## 8. Log rotation

```bash
sudo cp deploy/logrotate.conf /etc/logrotate.d/val-protection
sudo logrotate --debug /etc/logrotate.d/val-protection
```

## 9. Backups

The timer runs `backup` then `restore-test` every night:

- SQLite: an online backup through the SQLite backup API (consistent while the bot runs), file mode 0600, the last `BACKUP_KEEP` kept.
- PostgreSQL: `pg_dump --format=custom` with credentials passed through environment variables (never on the command line). Install `postgresql-client` matching your server version.

Copy `/var/backups/val-protection` off the server (for example with `restic` or `borg`), encrypted. Test a restore regularly:

```bash
sudo systemctl start val-protection-backup.service
journalctl -u val-protection-backup -n 20
```

### Restoring SQLite

```bash
sudo systemctl stop val-protection
sudo -u valprotection cp /var/backups/val-protection/val-protection-<timestamp>.db /var/lib/val-protection/val-protection.db
sudo -u valprotection rm -f /var/lib/val-protection/val-protection.db-wal /var/lib/val-protection/val-protection.db-shm
sudo systemctl start val-protection
```

### Restoring PostgreSQL

```bash
createdb -h <host> -U <user> val_protection_restore
pg_restore -h <host> -U <user> -d val_protection_restore --no-owner /var/backups/val-protection/val-protection-<timestamp>.dump
DATABASE_URL=postgres://<user>:<password>@<host>/val_protection_restore EVIDENCE_HMAC_KEY=<key> DATABASE_DRIVER=postgres node /opt/val-protection/dist/cli/verifyLogs.js
```

Switch `DATABASE_URL` to the restored database once verified.

## 10. PostgreSQL (larger installations)

```bash
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE ROLE valprotection LOGIN PASSWORD '<strong password>';"
sudo -u postgres psql -c "CREATE DATABASE val_protection OWNER valprotection;"
```

Then set `DATABASE_DRIVER=postgres` and `DATABASE_URL=postgres://valprotection:<password>@127.0.0.1:5432/val_protection` (URL-encode special characters). Use `sslmode=require` for a remote database. Migrations run at startup unless `MIGRATE_ON_START=false`, in which case run `npm run migrate` during deployments.

## 11. Redis (optional)

Redis is only useful when several processes share the same token or when you want counters to survive restarts.

```bash
sudo apt-get install -y redis-server
```

Bind it to `127.0.0.1`, set `requirepass`, and configure `REDIS_URL=redis://:<password>@127.0.0.1:6379/0` (`rediss://` for TLS). Val Protection refuses to start if Redis is configured but unreachable, rather than silently running with inconsistent counters.

## 12. Updates

```bash
cd /opt/val-protection
sudo git fetch && sudo git checkout <release tag>
sudo npm ci && sudo npm run build && sudo npm test && sudo npm prune --omit=dev
sudo systemctl start val-protection-backup.service
sudo systemctl restart val-protection
journalctl -u val-protection -n 50
```

Run `npm run audit:deps` regularly and review dependency updates before deploying them.

## Windows service

Val Protection runs on Windows with `npm start`. To run it as a service, use a service wrapper such as NSSM:

```powershell
nssm install ValProtection "C:\Program Files\nodejs\node.exe" "C:\val-protection\dist\index.js"
nssm set ValProtection AppDirectory C:\val-protection
nssm set ValProtection AppStdout C:\val-protection\logs\service.out.log
nssm set ValProtection AppStderr C:\val-protection\logs\service.err.log
nssm set ValProtection AppStopMethodConsole 15000
nssm start ValProtection
```

Val Protection reads `.env` from the working directory (`AppDirectory`), or from the path in `ENV_FILE`. Run it under a dedicated local account with read access to the application folder and write access only to `data`, `logs` and `backups`. Schedule `npm run backup` and `npm run restore-test` with Task Scheduler.

## Running several servers

One instance protects every server it is invited to; each server gets its own section under `guilds`. Use `global.allowedGuildIds` to make the instance ignore servers you did not plan for, and keep **Public Bot** disabled in the Developer Portal.
