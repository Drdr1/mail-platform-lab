# mail-platform-lab

A multi-domain mail platform on one Ubuntu 24.04 host: Postfix, Dovecot and
OpenDKIM, with every domain, mailbox and alias held in one SQLite database
and managed through a single CLI. Installed by an Ansible playbook, with
Terraform for a Google Cloud VM.

This is a lab, not a client system. CI installs the real stack on a runner
and tests it end to end with **150 mailboxes across 3 domains**.

## What it shows

| Area | How |
|---|---|
| Independent virtual mailboxes | Each mailbox has its own SMTP/IMAP credentials (SHA512-CRYPT), quota and hourly sending limit |
| One source of truth | Postfix reads `proxy:sqlite` maps, Dovecot a SQL passdb/userdb, the policy service the same file |
| Provisioning and lifecycle | `mp mailbox add / bulk / passwd / disable / enable / limit / delete` take effect immediately; no reloads |
| Per-domain DKIM | Key generated on `mp domain add`, OpenDKIM tables rebuilt and reloaded |
| DNS | `mp dns <domain>` prints MX, SPF, DKIM and DMARC records |
| Sending limits | Postfix policy service enforcing each mailbox's own hourly recipient limit |
| Security | No open relay, AUTH only after TLS, a mailbox can't send as another, plain IMAP closed, connection and auth rate limits |
| Monitoring | `mp metrics` writes Prometheus textfile metrics (mailboxes, storage, queue, rate-limited, auth failures) |
| Backup and recovery | `mp backup` / `mp restore`, including restoring one deleted mailbox without touching the rest |
| Google Workspace relay | Optional per-sender-domain relay through `smtp-relay.gmail.com` |

## Layout

```
mailplatform/   mp CLI: db, DKIM, DNS, metrics, backup/restore
policyd/        Postfix policy service (per-mailbox hourly limit)
ansible/        site.yml and templates for Postfix, Dovecot, OpenDKIM
terraform/gcp/  VM, static IP, firewall, daily disk snapshots
tests/          unit tests and integration tests against the live stack
docs/           architecture, operations, Workspace relay, sequencer integration, limits
```

## Quick start

```bash
# On an Ubuntu 24.04 host (or a fresh VM from terraform/gcp)
sudo ansible-playbook -i localhost, -c local ansible/site.yml -e mail_hostname=mail.example.net

sudo mp domain add example.com
sudo mp dns example.com --host mail.example.net --rua dmarc@example.com
printf 'sales@example.com\nsupport@example.com\n' > boxes.csv
sudo mp mailbox bulk --csv boxes.csv --limit 40     # prints address,password
sudo mp metrics
sudo mp backup /var/backups/mail-$(date +%F).tar.gz
```

## Tests

```bash
pytest tests/test_unit.py                     # anywhere
sudo MP_INTEGRATION=1 python3 -m pytest tests  # on a host configured by the playbook
```

The integration suite authenticates and sends over submission (587 and 465),
reads over IMAPS like a sequencing tool, verifies outbound DKIM signatures
cryptographically, and checks the refusal paths: wrong password, spoofed
sender, open relay attempt, plaintext auth, disabled or deleted mailbox, and
the hourly limit. No mail leaves the host.

## What a lab can't prove

Real deliverability depends on things only a production setup has: a clean IP
with a matching PTR record, a trusted TLS certificate, domain age and sending
history, and mailbox provider reputation. See [docs/limits.md](docs/limits.md).
