# Architecture

```
            Internet / sequencing tool (Instantly, Smartlead, mail clients)
                 |                    |                       |
              25 (inbound)    587 STARTTLS / 465 TLS      993 IMAPS
                 |                    |                       |
          +------v--------------------v------+        +-------v-------+
          |             Postfix              |        |    Dovecot    |
          |  smtpd :25  inbound only         |  SASL  |  IMAP, LMTP,  |
          |  submission :587 / :465 AUTH  <---------->|  auth         |
          |     check_policy_service ------+ |        +---^-------^---+
          |     milter -> OpenDKIM :8891   | |  LMTP      |       |
          |  virtual_transport ------------|-+------------+       |
          +---------+----------------------|-+                    |
                    |                      |                      |
           outbound | direct :25, or       |  policyd (spawn)     |
                    | relay :587           |  hourly limit        |
                    v                      v                      |
      MX of recipient /           /var/lib/mailplatform/          |
      smtp-relay.gmail.com          ratelimit.db                  |
                                                                  |
          +-------------------------------------------------------v--+
          | /etc/mailplatform/platform.db (SQLite)                   |
          | domains, mailboxes, aliases  <-- written only by `mp`     |
          +----------------------------------------------------------+
```

## Why these choices

- **SQLite as the single source of truth.** At hundreds of mailboxes on one
  host, a single file read by Postfix, Dovecot and the policy service removes
  the sync problems of separate map files, and needs no database server.
  Changes take effect on the next lookup with no reload. Moving to
  PostgreSQL later only changes the map definitions and the Dovecot `driver`.
- **Postfix + Dovecot over Mailcow.** Mailcow is a good all-in-one, but it runs
  around 15 containers and its own admin model. For a platform driven by
  automation and an external dashboard, plain Postfix/Dovecot with one schema
  is smaller, easier to audit and easier to script.
- **Dovecot LMTP delivery.** Quotas are enforced at delivery and Postfix never
  writes to mail storage directly.
- **A policy service for limits.** Postfix has no built-in per-user sending
  limit. The policy service reads each mailbox's `hourly_limit` from the
  database, so limits are per mailbox and changeable live.

## Ports and exposure

| Port | Service | Notes |
|---|---|---|
| 25 | Postfix smtpd | Inbound for hosted domains only; `reject_unauth_destination` with no `permit_mynetworks` |
| 587 | submission | STARTTLS required before AUTH |
| 465 | submissions | Implicit TLS |
| 993 | IMAPS | Plain IMAP on 143 is closed |
| 8891 | OpenDKIM | Loopback only |

## Security controls

- `reject_sender_login_mismatch`: a mailbox can only send as its own address.
- `smtpd_tls_auth_only` and Dovecot `disable_plaintext_auth`: no credentials
  without TLS. TLS 1.2 minimum.
- `smtpd_client_connection_rate_limit` and `smtpd_client_auth_rate_limit` per
  client IP.
- Services run unprivileged. The database is readable only by the
  `mailplatform` group (Postfix, Dovecot auth workers and the policy user);
  the policy user's rate database is private to it.
- Passwords are stored as SHA512-CRYPT and generated with 144 bits of
  randomness when not supplied.

## Google Cloud specifics

Google Cloud blocks outbound TCP 25 from all VMs. Inbound 25 works, so a GCP
host can receive directly but must send through a relay on 587 or 465:
Google Workspace SMTP relay for Workspace domains, or a sending provider.
See [workspace-relay.md](workspace-relay.md). On a VPS or dedicated server
with port 25 open, Postfix delivers directly.
