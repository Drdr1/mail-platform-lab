"""Prometheus textfile metrics for the node_exporter textfile collector."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import time

from . import db

RATE_DB = os.environ.get("MP_RATE_DB", "/var/lib/mailplatform/ratelimit.db")
DOVECOT_LOG = os.environ.get("MP_DOVECOT_LOG", "/var/log/dovecot.log")
VMAIL = os.environ.get("MP_VMAIL", "/var/vmail")


def queue_size() -> int:
    try:
        out = subprocess.run(["postqueue", "-j"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return -1
    return sum(1 for line in out.stdout.splitlines() if line.strip().startswith("{"))


def dir_bytes(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def auth_failures() -> int:
    try:
        with open(DOVECOT_LOG, errors="replace") as fh:
            return sum(1 for line in fh if "auth failed" in line or "Password mismatch" in line)
    except OSError:
        return 0


def rate_limited_last_hour() -> int:
    if not os.path.exists(RATE_DB):
        return 0
    conn = sqlite3.connect(RATE_DB)
    try:
        return conn.execute("SELECT count(*) FROM events WHERE accepted = 0 AND ts > ?",
                            (time.time() - 3600,)).fetchone()[0]
    except sqlite3.OperationalError:
        return 0
    finally:
        conn.close()


def render(db_path: str = db.DEFAULT_DB) -> str:
    conn = db.connect(db_path)
    lines = [
        "# HELP mp_mailboxes Mailboxes by domain and state.",
        "# TYPE mp_mailboxes gauge",
    ]
    for row in conn.execute(
            "SELECT domain, active, count(*) AS n FROM v_mailboxes GROUP BY domain, active"):
        state = "active" if row["active"] else "disabled"
        lines.append(f'mp_mailboxes{{domain="{row["domain"]}",state="{state}"}} {row["n"]}')
    lines += ["# HELP mp_maildir_bytes Mail storage used per domain.", "# TYPE mp_maildir_bytes gauge"]
    for d in db.list_domains(conn):
        lines.append(f'mp_maildir_bytes{{domain="{d["name"]}"}} {dir_bytes(os.path.join(VMAIL, d["name"]))}')
    conn.close()
    lines += [
        "# HELP mp_queue_messages Messages in the Postfix queue.", "# TYPE mp_queue_messages gauge",
        f"mp_queue_messages {queue_size()}",
        "# HELP mp_rate_limited_last_hour Recipients refused by the per-mailbox limit in the last hour.",
        "# TYPE mp_rate_limited_last_hour gauge",
        f"mp_rate_limited_last_hour {rate_limited_last_hour()}",
        "# HELP mp_auth_failures Failed IMAP/SMTP logins in the current Dovecot log.",
        "# TYPE mp_auth_failures gauge",
        f"mp_auth_failures {auth_failures()}",
    ]
    return "\n".join(lines) + "\n"
