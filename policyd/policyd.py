#!/usr/bin/env python3
"""Postfix policy service: per-mailbox hourly recipient limit.

Runs under Postfix spawn(8) on the submission port. For each RCPT TO from an
authenticated user it counts that mailbox's accepted recipients in the last
hour and answers 450 once the mailbox's own hourly_limit is reached. The
limit lives in the platform database, so `mp mailbox limit` changes it live.

Fails open (DUNNO) only when the request carries no SASL user, because the
submission service rejects unauthenticated clients before this check.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time

PLATFORM_DB = os.environ.get("MP_DB", "/etc/mailplatform/platform.db")
RATE_DB = os.environ.get("MP_RATE_DB", "/var/lib/mailplatform/ratelimit.db")
WINDOW = 3600


def rate_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(RATE_DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS events (address TEXT NOT NULL, ts REAL NOT NULL,"
                 " accepted INTEGER NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_events ON events (address, ts)")
    return conn


def hourly_limit(address: str) -> int | None:
    conn = sqlite3.connect(f"file:{PLATFORM_DB}?mode=ro", uri=True, timeout=10)
    try:
        row = conn.execute("SELECT hourly_limit FROM v_mailboxes WHERE address = ? AND active = 1",
                           (address,)).fetchone()
    finally:
        conn.close()
    return row[0] if row else None


def decide(request: dict[str, str], conn: sqlite3.Connection, now: float | None = None) -> str:
    now = time.time() if now is None else now
    user = request.get("sasl_username", "").lower()
    if not user or request.get("protocol_state", "RCPT") != "RCPT":
        return "DUNNO"
    limit = hourly_limit(user)
    if limit is None:
        return "REJECT 5.7.1 mailbox not active"
    with conn:
        conn.execute("DELETE FROM events WHERE ts < ?", (now - 2 * WINDOW,))
        used = conn.execute("SELECT count(*) FROM events WHERE address = ? AND accepted = 1"
                            " AND ts > ?", (user, now - WINDOW)).fetchone()[0]
        if used >= limit:
            conn.execute("INSERT INTO events VALUES (?, ?, 0)", (user, now))
            return f"450 4.7.1 hourly sending limit of {limit} recipients reached for {user}"
        conn.execute("INSERT INTO events VALUES (?, ?, 1)", (user, now))
    return "DUNNO"


def serve(stdin=sys.stdin, stdout=sys.stdout) -> None:
    conn = rate_conn()
    request: dict[str, str] = {}
    for line in stdin:
        line = line.rstrip("\n")
        if line:
            key, _, value = line.partition("=")
            request[key] = value
            continue
        try:
            action = decide(request, conn)
        except sqlite3.Error as exc:
            action = f"451 4.3.0 policy service error: {exc.__class__.__name__}"
        stdout.write(f"action={action}\n\n")
        stdout.flush()
        request = {}


if __name__ == "__main__":
    serve()
