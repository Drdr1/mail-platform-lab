"""Unit tests: no mail services needed."""
import io
import os
import sqlite3
import tarfile

import pytest

from mailplatform import backup, db, dns
from policyd import policyd


@pytest.fixture
def conn(tmp_path):
    path = str(tmp_path / "platform.db")
    db.init(path)
    c = db.connect(path)
    db.add_domain(c, "alpha.test", "mp1")
    c.commit()
    yield c
    c.close()


@pytest.mark.parametrize("name", ["-bad.test", "no_tld", "a..b.test", "x" * 64 + ".test", "UPPER..test"])
def test_invalid_domains_rejected(name):
    with pytest.raises(db.PlatformError):
        db.validate_domain(name)


@pytest.mark.parametrize("address", ["a@b@alpha.test", ".a@alpha.test", "a..b@alpha.test",
                                     "a b@alpha.test", "@alpha.test", "a@"])
def test_invalid_addresses_rejected(address):
    with pytest.raises(db.PlatformError):
        db.split_address(address)


def test_addresses_are_normalised(conn):
    db.add_mailbox(conn, "Sales.Team@Alpha.TEST", "{PLAIN}x")
    assert [m.address for m in db.list_mailboxes(conn)] == ["sales.team@alpha.test"]


def test_duplicate_mailbox_and_unknown_domain(conn):
    db.add_mailbox(conn, "a@alpha.test", "{PLAIN}x")
    with pytest.raises(db.PlatformError, match="already exists"):
        db.add_mailbox(conn, "a@alpha.test", "{PLAIN}x")
    with pytest.raises(db.PlatformError, match="unknown domain"):
        db.add_mailbox(conn, "a@beta.test", "{PLAIN}x")


def test_alias_and_mailbox_cannot_share_an_address(conn):
    db.add_mailbox(conn, "a@alpha.test", "{PLAIN}x")
    with pytest.raises(db.PlatformError):
        db.add_alias(conn, "a@alpha.test", "b@alpha.test")
    db.add_alias(conn, "sales@alpha.test", "a@alpha.test")
    with pytest.raises(db.PlatformError):
        db.add_mailbox(conn, "sales@alpha.test", "{PLAIN}x")


def test_disabling_domain_disables_its_mailboxes(conn):
    db.add_mailbox(conn, "a@alpha.test", "{PLAIN}x")
    conn.execute("UPDATE domains SET active = 0")
    assert db.list_mailboxes(conn)[0].active is False


def test_deleting_domain_cascades(conn):
    db.add_mailbox(conn, "a@alpha.test", "{PLAIN}x")
    conn.execute("DELETE FROM domains")
    assert conn.execute("SELECT count(*) FROM mailboxes").fetchone()[0] == 0


def test_long_txt_values_are_split_into_255_byte_strings():
    rec = dns.Record("mp1._domainkey.alpha.test", "TXT", "p=" + "A" * 400)
    strings = rec.zone_line().split(" IN TXT ")[1].split('" "')
    assert len(strings) == 2 and all(len(s.strip('"')) <= 255 for s in strings)


def test_dns_records():
    recs = dns.records("alpha.test", "mail.example.net", "mp1", "v=DKIM1; k=rsa; p=ABC",
                       dmarc_rua="dmarc@alpha.test", spf_includes=("_spf.google.com",))
    lines = [r.zone_line() for r in recs]
    assert lines[0] == "alpha.test. 3600 IN MX 10 mail.example.net."
    assert '"v=spf1 mx include:_spf.google.com -all"' in lines[1]
    assert lines[2].startswith("mp1._domainkey.alpha.test. 3600 IN TXT")
    assert "rua=mailto:dmarc@alpha.test" in lines[3]


class TestPolicy:
    @pytest.fixture
    def env(self, tmp_path, monkeypatch, conn):
        db.add_mailbox(conn, "a@alpha.test", "{PLAIN}x", hourly_limit=3)
        db.add_mailbox(conn, "off@alpha.test", "{PLAIN}x")
        db.set_mailbox(conn, "off@alpha.test", active=0)
        conn.commit()
        monkeypatch.setattr(policyd, "PLATFORM_DB", conn.execute("PRAGMA database_list").fetchone()[2])
        monkeypatch.setattr(policyd, "RATE_DB", str(tmp_path / "rate.db"))
        return policyd.rate_conn()

    def req(self, user):
        return {"protocol_state": "RCPT", "sasl_username": user}

    def test_limit_applies_per_hour(self, env):
        first = [policyd.decide(self.req("a@alpha.test"), env, now=1000 + i) for i in range(3)]
        assert first == ["DUNNO"] * 3
        assert policyd.decide(self.req("a@alpha.test"), env, now=1004).startswith("450 4.7.1")
        # an hour after the first three, the window has rolled forward
        assert policyd.decide(self.req("a@alpha.test"), env, now=1000 + 3601) == "DUNNO"

    def test_inactive_or_unknown_mailbox_rejected(self, env):
        assert policyd.decide(self.req("off@alpha.test"), env).startswith("REJECT")
        assert policyd.decide(self.req("ghost@alpha.test"), env).startswith("REJECT")

    def test_unauthenticated_and_other_stages_pass_through(self, env):
        assert policyd.decide({"protocol_state": "RCPT"}, env) == "DUNNO"
        assert policyd.decide({"protocol_state": "DATA", "sasl_username": "a@alpha.test"}, env) == "DUNNO"

    def test_wire_protocol(self, env):
        stdin = io.StringIO("request=smtpd_access_policy\nprotocol_state=RCPT\n"
                            "sasl_username=a@alpha.test\n\n" * 2)
        out = io.StringIO()
        policyd.serve(stdin, out)
        assert out.getvalue() == "action=DUNNO\n\naction=DUNNO\n\n"


def test_backup_and_single_mailbox_restore(tmp_path, monkeypatch, conn):
    vmail = tmp_path / "vmail"
    monkeypatch.setattr(backup, "VMAIL", str(vmail))
    db.add_mailbox(conn, "a@alpha.test", "{PLAIN}secret", hourly_limit=7)
    db.add_mailbox(conn, "b@alpha.test", "{PLAIN}other")
    conn.commit()
    for user in ("a", "b"):
        new = vmail / "alpha.test" / user / "Maildir" / "new"
        new.mkdir(parents=True)
        (new / "1.msg").write_text(f"Subject: for {user}\n\nhello\n")
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    archive = str(tmp_path / "backup.tar.gz")
    manifest = backup.create(archive, path)
    assert manifest["mailboxes"] == 2 and len(manifest["db_sha256"]) == 64
    assert oct(os.stat(archive).st_mode & 0o777) == "0o600"

    db.delete_mailbox(conn, "a@alpha.test")
    conn.commit()
    import shutil
    shutil.rmtree(vmail / "alpha.test" / "a")
    (vmail / "alpha.test" / "b" / "Maildir" / "new" / "2.msg").write_text("newer mail for b\n")

    assert backup.restore_mailbox(archive, "a@alpha.test", path) == 1
    row = sqlite3.connect(path).execute(
        "SELECT password_hash, hourly_limit FROM v_mailboxes WHERE address = 'a@alpha.test'").fetchone()
    assert row == ("{PLAIN}secret", 7)
    assert (vmail / "alpha.test" / "a" / "Maildir" / "new" / "1.msg").exists()
    # restoring one mailbox leaves the others alone
    assert (vmail / "alpha.test" / "b" / "Maildir" / "new" / "2.msg").exists()
    with pytest.raises(db.PlatformError, match="not in this backup"):
        backup.restore_mailbox(archive, "ghost@alpha.test", path)


def test_backup_archive_has_no_path_traversal(tmp_path, monkeypatch, conn):
    monkeypatch.setattr(backup, "VMAIL", str(tmp_path / "vmail"))
    path = conn.execute("PRAGMA database_list").fetchone()[2]
    archive = str(tmp_path / "b.tar.gz")
    backup.create(archive, path)
    with tarfile.open(archive) as tar:
        assert all(not m.name.startswith(("/", "..")) for m in tar.getmembers())
