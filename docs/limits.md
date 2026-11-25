# Limits: technical, provider policy, security, deliverability

## Technical

- **One host.** Fine for hundreds of mailboxes. Past that, split by domain
  across hosts, keep one central database (move it to PostgreSQL), and put
  provisioning behind an API.
- **SQLite writes.** Only the `mp` CLI writes the platform database, so
  write contention isn't an issue. The policy service writes its own file.
- **Outbound on Google Cloud.** Port 25 is blocked; sending needs a relay.

## Provider policy

- Google Workspace SMTP relay: own domains, own mail, within published daily
  limits. See [workspace-relay.md](workspace-relay.md).
- Cloud providers prohibit unsolicited bulk mail and can suspend a VM or
  account over abuse reports.
- Sequencing tools have their own sending rules and expect mailboxes on
  domains you control, with proper authentication.

## Security

- The database holds password hashes; back it up encrypted and off the host.
- Each mailbox is a credential set stored in a third-party tool. Rotate with
  `mp mailbox passwd` and disable unused mailboxes with `mp mailbox disable`.
- Keep SSH restricted to admin addresses (the Terraform requires them).

## Deliverability

A correct setup is necessary, but it isn't enough:

- **IP reputation.** A new IP has no history. A PTR record matching the mail
  hostname is required by major receivers.
- **Authentication alignment.** SPF, DKIM and DMARC must align with the From
  domain. DMARC starts at `p=none`; move to `quarantine` once reports are
  clean.
- **Bulk sender rules.** Gmail and Yahoo require authentication, one-click
  unsubscribe for bulk mail and low spam-complaint rates from bulk senders.
- **Volume and content.** New domains and mailboxes need to ramp up slowly.
  Many domains and mailboxes sending similar mail at volume is a pattern
  receivers look for, and authentication doesn't change that.
