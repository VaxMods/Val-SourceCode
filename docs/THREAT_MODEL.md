# Threat model

## Assets

| Asset | Why it matters |
| --- | --- |
| Server structure (channels, roles, permissions, webhooks) | Destroyed or hijacked in a nuke |
| Member base | Raided, spammed, phished, or mass-banned |
| Privileged access (Administrator, Manage Roles, Manage Server, Ban/Kick) | Gives every other capability |
| Val Protection's configuration and evidence | Disabling or blinding the bot precedes an attack; evidence supports recovery and accountability |
| Bot token and HMAC key | Full control of the bot / ability to forge evidence |

## Adversaries

| Adversary | Capabilities | Typical goal |
| --- | --- | --- |
| Raid operator | Hundreds of fresh or bought accounts, scripts, invite links | Flood, harass, shut down the server |
| Spammer / phisher | Compromised or new accounts, look-alike domains | Steal accounts and tokens |
| Rogue or compromised moderator | Legitimate permissions, knowledge of the server | Mass ban, privilege escalation, sabotage |
| Compromised administrator | Administrator permission | Nuke, disable protections, hide traces |
| Malicious bot | Whatever permissions it was given | Automated nuke, data exfiltration |
| Compromised owner account | Everything | Total takeover |
| Host-level attacker | Access to the VPS | Steal token, alter database |

## Scenarios and mitigations

| Scenario | Detection | Response | Residual risk |
| --- | --- | --- | --- |
| Join raid | Rate against adaptive baseline, risk signals, clusters | Lockdown (verification, invite pause), quarantine of suspects | Very slow, well-aged account raids look like organic growth |
| Slow wave of suspicious accounts | Suspicious joins in a long window | Incident, lockdown | Thresholds must be tuned per server |
| Rejoin after measure | Actioned users tracked 24h | Higher score, bypass incident | Fresh accounts are not linked to old ones |
| Mass ban/kick by moderator | Per-actor sliding window | Remove the role granting the permission, lockdown | Actions performed before the threshold are already done |
| Privilege escalation through role grant | Live audit entry + member update correlation | Revoke from recipient, restrict granter's role management | Grants by the owner, or roles above the bot |
| Privilege escalation through role edit | `ROLE_UPDATE` permission diff | Revert added dangerous bits, restrict actor | Administrator cannot be reverted without holding it |
| Malicious bot | `BOT_ADD`, risk factors, nuke engine | Logical quarantine, kick per policy, kick on destructive actions | Bot added with a role above Val Protection |
| Webhook abuse | Webhook audit entries | Delete unauthorized webhooks per policy | Messages already sent |
| Spam and phishing links | Content rules, link analysis | Ladder up to timeout, slowmode | Novel domains not matching heuristics |
| Disabling Val Protection | Bot role changes, roles removed, command permission changes, bot removed | Incidents, fallback webhook alert | An administrator above the bot can always kick it; the fallback alert is the last signal |
| Blinding alerts | Alert channel deletion, alert message deletion | Fallback webhook and file, incident | The evidence chain is unaffected; Discord-side history is lost |
| Reconfiguring the bot from Discord | Only the owner and security administrators can change settings; administrators and auditors are owner-only; weakening changes need confirmation and the owner by default; every choice is validated against the real server; ephemeral single-user panel sessions re-check access on every interaction | Every change and refusal recorded in the evidence chain and announced; moving the alert channel is also announced in the old channel | A compromised owner account; a security administrator account when the owner disabled owner approval for weakening changes |
| Erasing evidence | No delete command; HMAC chain; JSONL mirror; anchors | Integrity check alerts | A host attacker with the HMAC key can rewrite everything; truncating the newest records without the mirror is detectable only by comparing with the JSONL mirror or alerts already posted |
| Forging confirmations | Random 96-bit nonce, bound to user and guild, single use, 60s | Foreign presses are honeypot signals | – |
| Prototype pollution or injection through configuration | Strict schemas, safe merge, parameterized queries, no dynamic regex from config | Configuration refused | – |
| ReDoS through link or pattern rules | Domain lists and literal prefixes only, input length caps | – | – |
| Token or secret leakage in logs | Redaction in logger, evidence and alerts | – | Secrets printed by third-party libraries outside the logger |
| Database outage | Health monitor, fallback files | Protections continue in memory | Runtime overrides, whitelist and protected roles from the database are unavailable (file configuration applies) |
| Discord API outage | Every call returns an outcome; failures are recorded | Incidents marked "needs review" | Nothing can be enforced while Discord is down |

## Out of scope

- Protection against a compromised **owner** account: Discord gives the owner absolute power. Val Protection alerts; recovery requires Discord support.
- Protection against a host-level compromise: harden the VPS (see DEPLOYMENT.md). Keep the HMAC key out of the database and backups.
- Content moderation beyond spam and phishing heuristics (hate speech, NSFW detection).

## Security properties

1. Val Protection never bans automatically.
2. Val Protection never acts on an unknown author.
3. Val Protection takes no automatic action in monitor mode, except restoring its own decoy roles to zero privileges (a safety invariant, not a punishment). Commands run by authorized humans (lockdown, unlock, recover) work in every mode.
4. Every action records who, what, why, confidence and result.
5. Decoys never carry privileges; a privileged decoy is treated as a normal sensitive role and reported.
6. Lockdown is always time-bounded and never removes administrators' capabilities.
