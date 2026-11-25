# Connecting mailboxes to a sequencing tool

Instantly, Smartlead and similar tools connect each mailbox with its own
SMTP and IMAP credentials:

| Setting | Value |
|---|---|
| SMTP host | the platform hostname (must match the TLS certificate) |
| SMTP port | 587 (STARTTLS) or 465 (SSL/TLS) |
| IMAP host | the platform hostname |
| IMAP port | 993 (SSL/TLS) |
| Username | the full address |
| Password | from `mp mailbox add` or `mp mailbox bulk` |

`tests/test_integration.py::test_send_and_reply_like_a_sequencer` reproduces
this flow: send on 587, receive and verify DKIM over IMAPS, reply on 465,
read the reply with `In-Reply-To` intact.

## What to plan for before connecting many mailboxes

These follow from how the stack is configured. They are things to check
during a pilot, not reports from a production rollout.

- **A real certificate.** Sequencing tools verify TLS. Replace the
  self-signed certificate with one whose name matches the configured host.
- **Many mailboxes, few source IPs.** A tool logs in to every mailbox from a
  small pool of its own IPs. Postfix's `smtpd_client_auth_rate_limit` (20 per
  minute per IP here) and Dovecot's failed-login delay apply per IP, so at
  scale they can throttle the tool. Add the tool's published IP ranges to
  `smtpd_client_event_limit_exceptions` instead of raising the limits for
  everyone.
- **One wrong password slows the rest.** Dovecot delays repeated failed logins
  from the same IP. A mailbox with a stale password in the tool can slow logins
  for others sharing that IP. `mp_auth_failures` makes this visible.
- **Limits in two places.** Set the tool's daily cap below the mailbox's
  `hourly_limit` × sending hours, so the server-side limit is a safety net,
  not something the tool hits every day.
- **Sent folder.** Dovecot creates `Sent` with the `\Sent` special-use flag.
  Tools that save a copy over IMAP find it automatically.
