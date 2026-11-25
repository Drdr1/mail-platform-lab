"""Per-domain DKIM keys and the OpenDKIM tables generated from the database."""
from __future__ import annotations

import os
import re
import shutil
import subprocess

DKIM_DIR = os.environ.get("MP_DKIM_DIR", "/etc/opendkim")


def key_dir(domain: str) -> str:
    return os.path.join(DKIM_DIR, "keys", domain)


def generate_key(domain: str, selector: str, bits: int = 2048) -> None:
    """Create a key pair with opendkim-genkey unless one already exists."""
    d = key_dir(domain)
    if os.path.exists(os.path.join(d, f"{selector}.private")):
        return
    os.makedirs(d, exist_ok=True)
    subprocess.run(["opendkim-genkey", "-b", str(bits), "-d", domain, "-s", selector, "-D", d],
                   check=True)
    _chown_opendkim(d)


def _chown_opendkim(path: str) -> None:
    if shutil.which("chown") and _user_exists("opendkim"):
        subprocess.run(["chown", "-R", "opendkim:opendkim", path], check=True)
        for name in os.listdir(path):
            if name.endswith(".private"):
                os.chmod(os.path.join(path, name), 0o600)


def _user_exists(name: str) -> bool:
    try:
        import pwd
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def public_record(domain: str, selector: str) -> str:
    """Return the p=... TXT value from opendkim-genkey's .txt output, joined."""
    with open(os.path.join(key_dir(domain), f"{selector}.txt")) as fh:
        text = fh.read()
    return "".join(re.findall(r'"([^"]*)"', text))


def render_tables(domains: list[tuple[str, str]]) -> None:
    """Write KeyTable and SigningTable for the active (domain, selector) pairs."""
    key_lines, sign_lines = [], []
    for domain, selector in domains:
        name = f"{selector}._domainkey.{domain}"
        key_lines.append(f"{name} {domain}:{selector}:{key_dir(domain)}/{selector}.private")
        sign_lines.append(f"*@{domain} {name}")
    _atomic_write(os.path.join(DKIM_DIR, "KeyTable"), "\n".join(key_lines) + "\n")
    _atomic_write(os.path.join(DKIM_DIR, "SigningTable"), "\n".join(sign_lines) + "\n")


def _atomic_write(path: str, content: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def reload_opendkim() -> None:
    """OpenDKIM re-reads its configuration and tables on SIGUSR1."""
    subprocess.run(["pkill", "-USR1", "-x", "opendkim"], check=False)
