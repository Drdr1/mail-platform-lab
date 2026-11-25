"""Backups of the platform database, mail storage and DKIM keys, and restores.

An archive holds a consistent SQLite snapshot (online backup API), every
Maildir and the DKIM keys, plus a manifest with counts and a checksum.
A single mailbox can be restored without touching the others.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone

from . import db, dkim

VMAIL = os.environ.get("MP_VMAIL", "/var/vmail")


def maildir_home(address: str) -> str:
    local, domain = db.split_address(address)
    return os.path.join(VMAIL, domain, local)


def create(dest: str, db_path: str = db.DEFAULT_DB) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "platform.db")
        src = sqlite3.connect(db_path)
        out = sqlite3.connect(snap)
        with out:
            src.backup(out)
        src.close()
        out.close()
        with open(snap, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        conn = db.connect(snap)
        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "domains": conn.execute("SELECT count(*) FROM domains").fetchone()[0],
            "mailboxes": conn.execute("SELECT count(*) FROM mailboxes").fetchone()[0],
            "db_sha256": digest,
        }
        conn.close()
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(snap, arcname="platform.db")
            if os.path.isdir(VMAIL):
                tar.add(VMAIL, arcname="vmail")
            keys = os.path.join(dkim.DKIM_DIR, "keys")
            if os.path.isdir(keys):
                tar.add(keys, arcname="dkim-keys")
            data = json.dumps(manifest, indent=2).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    os.chmod(dest, 0o600)
    return manifest


def _safe_members(tar: tarfile.TarFile, prefix: str):
    for member in tar.getmembers():
        if member.name == prefix or member.name.startswith(prefix + "/"):
            yield member


def restore_mailbox(archive: str, address: str, db_path: str = db.DEFAULT_DB) -> int:
    """Restore one mailbox's row and Maildir. Returns the number of files restored."""
    local, domain = db.split_address(address)
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(archive, "r:gz") as tar:
        tar.extractall(tmp, members=list(_safe_members(tar, "platform.db")), filter="data")
        snap = db.connect(os.path.join(tmp, "platform.db"))
        row = snap.execute(
            "SELECT m.password_hash, m.quota_mb, m.hourly_limit, m.active FROM mailboxes m"
            " JOIN domains d ON d.id = m.domain_id WHERE m.local_part = ? AND d.name = ?",
            (local, domain)).fetchone()
        snap.close()
        if row is None:
            raise db.PlatformError(f"{address} is not in this backup")
        with db.connect(db_path) as conn:
            exists = conn.execute("SELECT 1 FROM v_mailboxes WHERE address = ?",
                                  (f"{local}@{domain}",)).fetchone()
            if exists:
                db.set_mailbox(conn, address, password_hash=row["password_hash"],
                               quota_mb=row["quota_mb"], hourly_limit=row["hourly_limit"],
                               active=row["active"])
            else:
                db.add_mailbox(conn, address, row["password_hash"], row["quota_mb"],
                               row["hourly_limit"])
        prefix = f"vmail/{domain}/{local}"
        members = list(_safe_members(tar, prefix))
        tar.extractall(tmp, members=members, filter="data")
        src = os.path.join(tmp, prefix)
        dst = maildir_home(address)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
            _chown_vmail(dst)
        return sum(1 for m in members if m.isfile())


def restore_all(archive: str, db_path: str = db.DEFAULT_DB) -> None:
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(archive, "r:gz") as tar:
        tar.extractall(tmp, filter="data")
        shutil.copy2(os.path.join(tmp, "platform.db"), db_path)
        if os.path.isdir(os.path.join(tmp, "vmail")):
            shutil.copytree(os.path.join(tmp, "vmail"), VMAIL, dirs_exist_ok=True)
            _chown_vmail(VMAIL)
        if os.path.isdir(os.path.join(tmp, "dkim-keys")):
            dest = os.path.join(dkim.DKIM_DIR, "keys")
            shutil.copytree(os.path.join(tmp, "dkim-keys"), dest, dirs_exist_ok=True)


def _chown_vmail(path: str) -> None:
    try:
        import pwd
        pw = pwd.getpwnam("vmail")
    except KeyError:
        return
    for root, dirs, files in os.walk(path):
        os.chown(root, pw.pw_uid, pw.pw_gid)
        for name in files:
            os.chown(os.path.join(root, name), pw.pw_uid, pw.pw_gid)
