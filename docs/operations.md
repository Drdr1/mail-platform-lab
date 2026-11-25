# Operations

## Day to day

```bash
sudo mp domain add example.com           # creates the DKIM key, reloads OpenDKIM
sudo mp dns example.com --host mail.example.net --rua dmarc@example.com
sudo mp mailbox add anna@example.com     # prints address,password
sudo mp mailbox bulk --csv new.csv       # address[,password] per line
sudo mp mailbox limit anna@example.com --value 30
sudo mp mailbox passwd anna@example.com  # rotates; prints the new password
sudo mp mailbox disable anna@example.com # logins and inbound mail refused
sudo mp mailbox delete anna@example.com  # data moved to /var/vmail/.deleted
sudo mp alias sales@example.com anna@example.com
```

## Monitoring

Run `mp metrics --out /var/lib/node_exporter/textfile/mail.prom` from a
systemd timer or cron every minute and let node_exporter's textfile collector
expose it. Alert on:

- `mp_queue_messages` above a baseline for 15 minutes: delivery is stuck.
- `mp_auth_failures` rising quickly: a credential problem or a brute-force attempt.
- `mp_rate_limited_last_hour` above 0 for a mailbox you didn't expect: the
  sequencing tool's cap is set above the server limit.

Logs: `/var/log/postfix.log`, `/var/log/dovecot.log`, and syslog for OpenDKIM.

## Backups

`mp backup` writes a consistent database snapshot, every Maildir and the DKIM
keys into one archive (mode 0600) with a manifest and checksum. Run it daily
and copy the archive off the host, encrypted. The Terraform also takes daily
disk snapshots.

Restore one mailbox:

```bash
sudo mp restore /var/backups/mail-2026-11-25.tar.gz --mailbox anna@example.com
```

Restore everything onto a fresh host: apply the playbook, then
`sudo mp restore <archive>`.

## Moving to production

1. Replace the self-signed certificate (certbot with the mail hostname), and
   set `self_signed_tls: false`.
2. Ask the provider for a PTR record matching the mail hostname.
3. Publish the records from `mp dns` for each domain.
4. Exempt the sequencing tool's IP ranges from per-IP rate limits
   (see sequencer-integration.md).
