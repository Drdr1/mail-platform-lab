# Google Workspace SMTP relay

Set `workspace_relay_domains` in the playbook and Postfix sends mail from those
sender domains through `smtp-relay.gmail.com:587` with TLS required. Other
domains keep their normal route.

```bash
sudo ansible-playbook -i localhost, -c local ansible/site.yml \
  -e '{"workspace_relay_domains": ["example.com"]}'
```

This writes `sender_dependent_relayhost_maps` and a TLS policy that refuses to
send to the relay without TLS 1.2.

## Google Admin console side

In the Admin console, under the Gmail routing settings, add an SMTP relay
service entry:

- **Allowed senders:** prefer "Only addresses in my domains". It stops the
  relay from carrying mail for domains outside the Workspace account.
- **Authentication:** allow only this server's static IP. SMTP AUTH with a
  Workspace account is possible but adds a credential to protect.
- **Require TLS encryption:** on.

## Policy limits to respect

- The relay is for the organisation's own mail from its own Workspace domains.
  A sender domain must be one of the account's domains.
- Google publishes daily relay limits per user and per account, tied to the
  number of licences. Check the current figures before sizing anything, and
  keep each mailbox's `hourly_limit` well inside them.
- Using the relay to carry bulk unsolicited mail, or to send for mailboxes
  that aren't Workspace users so their volume counts against fewer licences,
  breaks Workspace terms. The likely result is a suspended relay, and
  possibly the account. If the goal is high-volume sending, a dedicated
  sending provider is the honest route.

The lab includes the configuration but can't test it: it needs a real
Workspace account and an allowlisted IP.
