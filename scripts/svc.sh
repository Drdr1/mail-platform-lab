#!/bin/sh
# Restart the mail services, with or without systemd (CI runners vs containers),
# then wait until every listener is up so callers never race a half-started stack.
set -e
wait_gone() { i=0; while pgrep -x "$1" >/dev/null && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done; }
if [ -d /run/systemd/system ]; then
  systemctl restart opendkim dovecot postfix
else
  mkdir -p /run/opendkim && chown opendkim:opendkim /run/opendkim
  pkill -x opendkim 2>/dev/null || true; wait_gone opendkim
  rm -f /run/opendkim/opendkim.pid
  opendkim -x /etc/opendkim.conf
  doveadm stop 2>/dev/null || true; wait_gone dovecot
  dovecot
  postfix stop 2>/dev/null || true; wait_gone master
  postfix start
fi
for port in 8891 25 587 465 993; do
  i=0
  until ss -ltn "sport = :$port" | grep -q LISTEN; do
    i=$((i+1)); [ $i -gt 100 ] && { echo "port $port not listening" >&2; exit 1; }
    sleep 0.2
  done
done
echo "mail services up"
