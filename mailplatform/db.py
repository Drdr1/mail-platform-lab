"""SQLite source of truth for domains, mailboxes and aliases.

Postfix (via proxy:sqlite maps), Dovecot (sql passdb) and the rate-limit
policy service all read this one file. Only the `mp` CLI writes to it.
"""
from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass

DEFAULT_DB = os.environ.get("MP_DB", "/etc/mailplatform/platform.db")

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS domains (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    active        INTEGER NOT NULL DEFAULT 1,
    dkim_selector TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS mailboxes (
    id            INTEGER PRIMARY KEY,
    domain_id     INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    local_part    TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    quota_mb      INTEGER NOT NULL DEFAULT 2048,
    hourly_limit  INTEGER NOT NULL DEFAULT 50,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (domain_id, local_part)
);
CREATE TABLE IF NOT EXISTS aliases (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL UNIQUE,
    destination TEXT NOT NULL
);
CREATE VIEW IF NOT EXISTS v_mailboxes AS
    SELECT m.local_part || '@' || d.name AS address,
           m.local_part, d.name AS domain, m.password_hash, m.quota_mb,
           m.hourly_limit, (m.active AND d.active) AS active
    FROM mailboxes m JOIN domains d ON d.id = m.domain_id;
"""

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
LOCAL_RE = re.compile(r"^[a-z0-9]([a-z0-9._+-]{0,62}[a-z0-9])?$")


class PlatformError(Exception):
    pass


@dataclass
class Mailbox:
    address: str
    domain: str
    quota_mb: int
    hourly_limit: int
    active: bool


def connect(path: str = DEFAULT_DB) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init(path: str = DEFAULT_DB) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def validate_domain(name: str) -> str:
    name = name.strip().lower()
    if not DOMAIN_RE.match(name):
        raise PlatformError(f"invalid domain name: {name!r}")
    return name


def split_address(address: str) -> tuple[str, str]:
    address = address.strip().lower()
    if address.count("@") != 1:
        raise PlatformError(f"invalid address: {address!r}")
    local, domain = address.split("@")
    if not LOCAL_RE.match(local) or ".." in local:
        raise PlatformError(f"invalid local part: {local!r}")
    return local, validate_domain(domain)


def domain_id(conn: sqlite3.Connection, name: str) -> int:
    row = conn.execute("SELECT id FROM domains WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise PlatformError(f"unknown domain: {name}")
    return row["id"]


def add_domain(conn: sqlite3.Connection, name: str, selector: str) -> None:
    name = validate_domain(name)
    try:
        conn.execute("INSERT INTO domains (name, dkim_selector) VALUES (?, ?)", (name, selector))
    except sqlite3.IntegrityError:
        raise PlatformError(f"domain already exists: {name}") from None


def add_mailbox(conn, address: str, password_hash: str, quota_mb: int = 2048,
                hourly_limit: int = 50) -> None:
    local, domain = split_address(address)
    did = domain_id(conn, domain)
    if conn.execute("SELECT 1 FROM aliases WHERE source = ?", (f"{local}@{domain}",)).fetchone():
        raise PlatformError(f"address is already an alias: {address}")
    try:
        conn.execute(
            "INSERT INTO mailboxes (domain_id, local_part, password_hash, quota_mb, hourly_limit)"
            " VALUES (?, ?, ?, ?, ?)",
            (did, local, password_hash, quota_mb, hourly_limit),
        )
    except sqlite3.IntegrityError:
        raise PlatformError(f"mailbox already exists: {address}") from None


def _mailbox_row(conn, address: str):
    local, domain = split_address(address)
    row = conn.execute(
        "SELECT m.id FROM mailboxes m JOIN domains d ON d.id = m.domain_id"
        " WHERE m.local_part = ? AND d.name = ?", (local, domain)).fetchone()
    if row is None:
        raise PlatformError(f"unknown mailbox: {address}")
    return row["id"]


def set_mailbox(conn, address: str, **fields) -> None:
    allowed = {"password_hash", "quota_mb", "hourly_limit", "active"}
    bad = set(fields) - allowed
    if bad:
        raise PlatformError(f"cannot set {sorted(bad)}")
    mid = _mailbox_row(conn, address)
    for key, value in fields.items():
        conn.execute(f"UPDATE mailboxes SET {key} = ? WHERE id = ?", (value, mid))


def delete_mailbox(conn, address: str) -> None:
    conn.execute("DELETE FROM mailboxes WHERE id = ?", (_mailbox_row(conn, address),))


def list_mailboxes(conn, domain: str | None = None) -> list[Mailbox]:
    sql = "SELECT address, domain, quota_mb, hourly_limit, active FROM v_mailboxes"
    args: tuple = ()
    if domain:
        sql += " WHERE domain = ?"
        args = (validate_domain(domain),)
    return [Mailbox(r["address"], r["domain"], r["quota_mb"], r["hourly_limit"], bool(r["active"]))
            for r in conn.execute(sql + " ORDER BY address", args)]


def list_domains(conn) -> list[sqlite3.Row]:
    return conn.execute("SELECT name, active, dkim_selector FROM domains ORDER BY name").fetchall()


def add_alias(conn, source: str, destination: str) -> None:
    s_local, s_domain = split_address(source)
    split_address(destination)
    domain_id(conn, s_domain)
    exists = conn.execute(
        "SELECT 1 FROM v_mailboxes WHERE address = ?", (f"{s_local}@{s_domain}",)).fetchone()
    if exists:
        raise PlatformError(f"address is already a mailbox: {source}")
    conn.execute("INSERT INTO aliases (source, destination) VALUES (?, ?)",
                 (f"{s_local}@{s_domain}", destination.lower()))
