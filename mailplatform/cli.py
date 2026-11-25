"""`mp` — the operator CLI for domains, mailboxes, DNS, metrics and backups."""
from __future__ import annotations

import argparse
import csv
import os
import secrets
import shutil
import subprocess
import sys
from datetime import datetime

from . import backup, db, dkim, dns, metrics

MAIL_HOST = os.environ.get("MP_MAIL_HOST", "mail.example.net")
DEFAULT_SELECTOR = os.environ.get("MP_DKIM_SELECTOR", "mp1")


def hash_password(password: str) -> str:
    out = subprocess.run(["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def new_password() -> str:
    return secrets.token_urlsafe(18)


def sync_dkim(conn) -> None:
    active = [(r["name"], r["dkim_selector"]) for r in db.list_domains(conn) if r["active"]]
    dkim.render_tables(active)
    dkim.reload_opendkim()


def cmd_init(args) -> None:
    db.init(args.db)
    print(f"initialised {args.db}")


def cmd_domain(args) -> None:
    with db.connect(args.db) as conn:
        if args.action == "add":
            name = db.validate_domain(args.name)
            db.add_domain(conn, name, args.selector)
            dkim.generate_key(name, args.selector)
            sync_dkim(conn)
            print(f"added {name} (DKIM selector {args.selector})")
        elif args.action in ("disable", "enable"):
            conn.execute("UPDATE domains SET active = ? WHERE id = ?",
                         (1 if args.action == "enable" else 0, db.domain_id(conn, args.name)))
            sync_dkim(conn)
            print(f"{args.action}d {args.name}")
        elif args.action == "list":
            for row in db.list_domains(conn):
                print(f'{row["name"]}\t{"active" if row["active"] else "disabled"}\t{row["dkim_selector"]}')


def cmd_dns(args) -> None:
    conn = db.connect(args.db)
    row = conn.execute("SELECT dkim_selector FROM domains WHERE name = ?",
                       (db.validate_domain(args.name),)).fetchone()
    if row is None:
        raise db.PlatformError(f"unknown domain: {args.name}")
    for rec in dns.records(args.name, args.host, row["dkim_selector"],
                           dkim.public_record(args.name, row["dkim_selector"]),
                           dmarc_rua=args.rua, spf_includes=tuple(args.spf_include or ())):
        print(rec.zone_line())


def _password_from(args) -> tuple[str, bool]:
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n"), False
    return new_password(), True


def cmd_mailbox(args) -> None:
    with db.connect(args.db) as conn:
        if args.action == "add":
            password, generated = _password_from(args)
            db.add_mailbox(conn, args.address, hash_password(password), args.quota, args.limit)
            print(f"{args.address.lower()},{password}" if generated else f"added {args.address}")
        elif args.action == "bulk":
            writer = csv.writer(sys.stdout)
            with open(args.csv) as fh:
                for row in csv.reader(fh):
                    if not row or row[0].startswith("#"):
                        continue
                    address = row[0].strip()
                    password = row[1].strip() if len(row) > 1 and row[1].strip() else new_password()
                    db.add_mailbox(conn, address, hash_password(password), args.quota, args.limit)
                    writer.writerow([address.lower(), password])
        elif args.action == "passwd":
            password, generated = _password_from(args)
            db.set_mailbox(conn, args.address, password_hash=hash_password(password))
            print(f"{args.address.lower()},{password}" if generated else f"updated {args.address}")
        elif args.action in ("disable", "enable"):
            db.set_mailbox(conn, args.address, active=1 if args.action == "enable" else 0)
            print(f"{args.action}d {args.address}")
        elif args.action == "limit":
            db.set_mailbox(conn, args.address, hourly_limit=args.value)
            print(f"{args.address} hourly limit {args.value}")
        elif args.action == "delete":
            db.delete_mailbox(conn, args.address)
            home = backup.maildir_home(args.address)
            if os.path.isdir(home):
                if args.purge:
                    shutil.rmtree(home)
                else:
                    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    archive = os.path.join(backup.VMAIL, ".deleted", f"{args.address.lower()}-{stamp}")
                    os.makedirs(os.path.dirname(archive), exist_ok=True)
                    shutil.move(home, archive)
            print(f"deleted {args.address}")
        elif args.action == "list":
            for m in db.list_mailboxes(conn, args.domain):
                state = "active" if m.active else "disabled"
                print(f"{m.address}\t{state}\tlimit={m.hourly_limit}/h\tquota={m.quota_mb}MB")


def cmd_alias(args) -> None:
    with db.connect(args.db) as conn:
        db.add_alias(conn, args.source, args.destination)
    print(f"{args.source} -> {args.destination}")


def cmd_metrics(args) -> None:
    text = metrics.render(args.db)
    if args.out:
        tmp = args.out + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(text)
        os.replace(tmp, args.out)
    else:
        sys.stdout.write(text)


def cmd_backup(args) -> None:
    manifest = backup.create(args.dest, args.db)
    print(f'backup {args.dest}: {manifest["domains"]} domains, {manifest["mailboxes"]} mailboxes')


def cmd_restore(args) -> None:
    if args.mailbox:
        n = backup.restore_mailbox(args.archive, args.mailbox, args.db)
        print(f"restored {args.mailbox} ({n} files)")
    else:
        backup.restore_all(args.archive, args.db)
        with db.connect(args.db) as conn:
            sync_dkim(conn)
        print("restored full backup")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mp", description="Multi-domain mail platform admin")
    p.add_argument("--db", default=db.DEFAULT_DB)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(func=cmd_init)

    d = sub.add_parser("domain")
    d.add_argument("action", choices=["add", "disable", "enable", "list"])
    d.add_argument("name", nargs="?")
    d.add_argument("--selector", default=DEFAULT_SELECTOR)
    d.set_defaults(func=cmd_domain)

    n = sub.add_parser("dns")
    n.add_argument("name")
    n.add_argument("--host", default=MAIL_HOST)
    n.add_argument("--rua")
    n.add_argument("--spf-include", action="append")
    n.set_defaults(func=cmd_dns)

    m = sub.add_parser("mailbox")
    m.add_argument("action", choices=["add", "bulk", "passwd", "disable", "enable", "limit",
                                      "delete", "list"])
    m.add_argument("address", nargs="?")
    m.add_argument("--csv")
    m.add_argument("--domain")
    m.add_argument("--password-stdin", action="store_true")
    m.add_argument("--quota", type=int, default=2048)
    m.add_argument("--limit", type=int, default=50)
    m.add_argument("--value", type=int)
    m.add_argument("--purge", action="store_true")
    m.set_defaults(func=cmd_mailbox)

    a = sub.add_parser("alias")
    a.add_argument("source")
    a.add_argument("destination")
    a.set_defaults(func=cmd_alias)

    me = sub.add_parser("metrics")
    me.add_argument("--out")
    me.set_defaults(func=cmd_metrics)

    b = sub.add_parser("backup")
    b.add_argument("dest")
    b.set_defaults(func=cmd_backup)

    r = sub.add_parser("restore")
    r.add_argument("archive")
    r.add_argument("--mailbox")
    r.set_defaults(func=cmd_restore)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except db.PlatformError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
