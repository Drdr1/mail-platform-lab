"""Integration tests against the real Postfix/Dovecot/OpenDKIM stack.

Run as root on a host configured by ansible/site.yml:
    MP_INTEGRATION=1 pytest -m integration

The tests act the way a sequencing tool such as Instantly does: authenticate
over SMTP submission and IMAP with a mailbox's own credentials, send, then
read replies. Everything stays on this host; no mail leaves it.
"""
import csv
import email
import imaplib
import io
import os
import random
import shutil
import smtplib
import ssl
import subprocess
import time
import uuid
from email.message import EmailMessage

import dkim as dkimpy
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("MP_INTEGRATION") != "1", reason="set MP_INTEGRATION=1"),
]

HOST = "127.0.0.1"
DOMAINS = ["alpha.test", "beta.test", "gamma.test"]
PER_DOMAIN = 50
# The lab uses a self-signed certificate; production uses a real one and verifies it.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def mp(*args, stdin=None) -> str:
    out = subprocess.run(["mp", *args], input=stdin, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"mp {' '.join(args)} failed: {out.stderr.strip()}")
    return out.stdout


@pytest.fixture(scope="session")
def creds():
    """Fresh platform with 3 domains x 50 mailboxes. Returns {address: password}."""
    subprocess.run(["sqlite3", "/etc/mailplatform/platform.db",
                    "PRAGMA foreign_keys=ON; DELETE FROM aliases; DELETE FROM domains;"], check=True)
    for name in os.listdir("/var/vmail"):
        shutil.rmtree(os.path.join("/var/vmail", name))
    # Clear rows rather than deleting the file: running policy processes keep it open.
    # Run as the policy user so no root-owned journal files appear.
    if os.path.getsize("/var/lib/mailplatform/ratelimit.db") if os.path.exists(
            "/var/lib/mailplatform/ratelimit.db") else 0:
        subprocess.run(["setpriv", "--reuid=mppolicy", "--regid=mailplatform", "--clear-groups",
                        "sqlite3", "/var/lib/mailplatform/ratelimit.db", "DELETE FROM events;"],
                       check=True)
    for d in DOMAINS:
        mp("domain", "add", d)
    csv_path = "/tmp/mp-bulk.csv"
    with open(csv_path, "w") as fh:
        for d in DOMAINS:
            for i in range(PER_DOMAIN):
                fh.write(f"user{i:02d}@{d}\n")
    out = mp("mailbox", "bulk", "--csv", csv_path)
    os.remove(csv_path)
    result = {row[0]: row[1] for row in csv.reader(io.StringIO(out))}
    time.sleep(1)  # OpenDKIM reloads its tables on SIGUSR1
    return result


def pick(creds, n, domain=None):
    pool = sorted(a for a in creds if domain is None or a.endswith("@" + domain))
    return random.Random(n).sample(pool, n)


def submit(user, password, msg, port=587):
    if port == 465:
        smtp = smtplib.SMTP_SSL(HOST, 465, context=TLS, timeout=20)
    else:
        smtp = smtplib.SMTP(HOST, port, timeout=20)
        smtp.starttls(context=TLS)
    with smtp:
        smtp.login(user, password)
        smtp.send_message(msg)


def make(sender, to, subject, **headers):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg["Message-ID"] = f"<{uuid.uuid4()}@{sender.split('@')[1]}>"
    for key, value in headers.items():
        msg[key.replace("_", "-")] = value
    msg.set_content(f"{subject}\n")
    return msg


def fetch(user, password, message_id, timeout=20) -> bytes:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with imaplib.IMAP4_SSL(HOST, 993, ssl_context=TLS) as imap:
            imap.login(user, password)
            imap.select("INBOX")
            _, data = imap.search(None, "HEADER", "Message-ID", message_id)
            if data[0]:
                _, parts = imap.fetch(data[0].split()[-1], "(RFC822)")
                return parts[0][1]
        time.sleep(0.5)
    raise AssertionError(f"{message_id} never reached {user}")


def dkim_dns(name, timeout=5):
    selector, _, domain = name.decode().rstrip(".").partition("._domainkey.")
    value = subprocess.run(["sh", "-c", f"cat /etc/opendkim/keys/{domain}/{selector}.txt"],
                           capture_output=True, text=True).stdout
    return "".join(part.split('"')[1] for part in value.split("\n") if '"' in part).encode()


def test_150_mailboxes_provisioned_and_visible_to_dovecot(creds):
    assert len(creds) == len(DOMAINS) * PER_DOMAIN
    assert len(mp("mailbox", "list").splitlines()) == 150
    users = subprocess.run(["doveadm", "user", "*"], capture_output=True, text=True, check=True)
    assert len(users.stdout.split()) == 150


def test_send_and_reply_like_a_sequencer(creds):
    a, = pick(creds, 1, "alpha.test")
    b, = pick(creds, 1, "beta.test")
    first = make(a, b, "intro")
    submit(a, creds[a], first, port=587)
    raw = fetch(b, creds[b], first["Message-ID"])
    assert dkimpy.verify(raw, dnsfunc=dkim_dns), "outbound DKIM signature must verify"
    assert b"d=alpha.test" in raw

    reply = make(b, a, "Re: intro", In_Reply_To=first["Message-ID"], References=first["Message-ID"])
    submit(b, creds[b], reply, port=465)
    got = email.message_from_bytes(fetch(a, creds[a], reply["Message-ID"]))
    assert got["In-Reply-To"] == first["Message-ID"]
    assert dkimpy.verify(got.as_bytes(), dnsfunc=dkim_dns)


def test_tampered_message_fails_dkim(creds):
    a, b = pick(creds, 2, "gamma.test")
    msg = make(a, b, "integrity")
    submit(a, creds[a], msg)
    raw = fetch(b, creds[b], msg["Message-ID"])
    assert not dkimpy.verify(raw.replace(b"integrity", b"tampered!"), dnsfunc=dkim_dns)


def test_wrong_password_is_rejected_on_smtp_and_imap(creds):
    a, = pick(creds, 1)
    with smtplib.SMTP(HOST, 587, timeout=20) as smtp:
        smtp.starttls(context=TLS)
        with pytest.raises(smtplib.SMTPAuthenticationError):
            smtp.login(a, "wrong-password")
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=TLS) as imap:
        with pytest.raises(imaplib.IMAP4.error):
            imap.login(a, "wrong-password")


def test_auth_is_not_offered_before_tls():
    with smtplib.SMTP(HOST, 587, timeout=20) as smtp:
        smtp.ehlo()
        assert not smtp.has_extn("auth")
    with pytest.raises(ConnectionRefusedError):
        imaplib.IMAP4(HOST, 143)  # plain IMAP is closed entirely


def test_mailbox_cannot_send_as_another_mailbox(creds):
    a, other, to = pick(creds, 3, "alpha.test")
    with pytest.raises(smtplib.SMTPException) as exc:
        submit(a, creds[a], make(other, to, "spoof"))
    assert "553" in str(exc.value) or "not owned" in str(exc.value)


def test_port_25_is_not_an_open_relay(creds):
    with smtplib.SMTP(HOST, 25, timeout=20) as smtp:
        smtp.ehlo("outside.example")
        smtp.mail("someone@outside.example")
        code, text = smtp.rcpt("victim@example.org")
        assert code in (454, 554) and b"Relay access denied" in text


def test_port_25_accepts_inbound_for_hosted_mailboxes_only(creds):
    b, = pick(creds, 1, "beta.test")
    inbound = make("sender@outside.example", b, "inbound")
    with smtplib.SMTP(HOST, 25, timeout=20) as smtp:
        smtp.ehlo("outside.example")
        smtp.send_message(inbound)
        smtp.mail("sender@outside.example")
        code, _ = smtp.rcpt("nobody@beta.test")
        assert code == 550
    raw = fetch(b, creds[b], inbound["Message-ID"])
    assert b"Delivered-To: " + b.encode() in raw


def test_hourly_limit_defers_extra_recipients(creds):
    sender, *rcpts = pick(creds, 5, "gamma.test")
    mp("mailbox", "limit", sender, "--value", "3")
    with smtplib.SMTP(HOST, 587, timeout=20) as smtp:
        smtp.starttls(context=TLS)
        smtp.login(sender, creds[sender])
        smtp.mail(sender)
        codes = [smtp.rcpt(r)[0] for r in rcpts]
    assert codes == [250, 250, 250, 450]
    metrics = mp("metrics")
    assert "mp_rate_limited_last_hour 1" in metrics


def test_disable_enable_delete_lifecycle(creds):
    victim, sender = pick(creds, 2, "beta.test")
    mp("mailbox", "disable", victim)
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=TLS) as imap:
        with pytest.raises(imaplib.IMAP4.error):
            imap.login(victim, creds[victim])
    with smtplib.SMTP(HOST, 25, timeout=20) as smtp:
        smtp.ehlo("outside.example")
        smtp.mail("x@outside.example")
        assert smtp.rcpt(victim)[0] == 550

    mp("mailbox", "enable", victim)
    msg = make(sender, victim, "back")
    submit(sender, creds[sender], msg)
    fetch(victim, creds[victim], msg["Message-ID"])

    mp("mailbox", "delete", victim)
    local, domain = victim.split("@")
    assert not os.path.exists(f"/var/vmail/{domain}/{local}")
    archived = [n for n in os.listdir("/var/vmail/.deleted") if n.startswith(victim)]
    assert archived, "deleted mailbox data is archived, not destroyed"
    with smtplib.SMTP(HOST, 587, timeout=20) as smtp:
        smtp.starttls(context=TLS)
        with pytest.raises(smtplib.SMTPAuthenticationError):
            smtp.login(victim, creds[victim])


def test_password_rotation(creds):
    a, = pick(creds, 1, "gamma.test")
    out = mp("mailbox", "passwd", a).strip()
    new = out.split(",", 1)[1]
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=TLS) as imap:
        with pytest.raises(imaplib.IMAP4.error):
            imap.login(a, creds[a])
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=TLS) as imap:
        imap.login(a, new)
    creds[a] = new


def test_alias_delivers_to_mailbox(creds):
    target, sender = pick(creds, 2, "alpha.test")
    mp("alias", "sales@alpha.test", target)
    msg = make(sender, "sales@alpha.test", "alias")
    submit(sender, creds[sender], msg)
    fetch(target, creds[target], msg["Message-ID"])


def test_backup_then_restore_one_deleted_mailbox(creds, tmp_path):
    victim, sender = pick(creds, 2, "gamma.test")
    msg = make(sender, victim, "keep me")
    submit(sender, creds[sender], msg)
    fetch(victim, creds[victim], msg["Message-ID"])
    archive = str(tmp_path / "platform-backup.tar.gz")
    assert "3 domains" in mp("backup", archive)

    mp("mailbox", "delete", victim, "--purge")
    with imaplib.IMAP4_SSL(HOST, 993, ssl_context=TLS) as imap:
        with pytest.raises(imaplib.IMAP4.error):
            imap.login(victim, creds[victim])

    mp("restore", archive, "--mailbox", victim)
    assert fetch(victim, creds[victim], msg["Message-ID"], timeout=5)


def test_dns_records_and_metrics(creds):
    zone = mp("dns", "alpha.test", "--host", "mail.example.net", "--rua", "dmarc@alpha.test")
    assert "IN MX 10 mail.example.net." in zone
    assert "v=spf1 mx -all" in zone
    assert "mp1._domainkey.alpha.test." in zone and "p=" in zone
    assert "_dmarc.alpha.test." in zone
    metrics = mp("metrics")
    assert 'mp_mailboxes{domain="alpha.test",state="active"}' in metrics
    assert "mp_queue_messages" in metrics
