"""DNS records each domain needs. Printed for the operator or a DNS API."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Record:
    name: str
    type: str
    value: str
    priority: int | None = None

    def zone_line(self) -> str:
        if self.type == "TXT":
            # DNS TXT strings are limited to 255 bytes; 2048-bit DKIM keys need splitting.
            chunks = [self.value[i:i + 255] for i in range(0, len(self.value), 255)]
            value = " ".join(f'"{c}"' for c in chunks)
        else:
            value = self.value
        prio = f"{self.priority} " if self.priority is not None else ""
        return f"{self.name}. 3600 IN {self.type} {prio}{value}"


def records(domain: str, mail_host: str, selector: str, dkim_value: str,
            dmarc_rua: str | None = None, spf_includes: tuple[str, ...] = ()) -> list[Record]:
    spf = "v=spf1 mx " + "".join(f"include:{inc} " for inc in spf_includes) + "-all"
    dmarc = "v=DMARC1; p=none; adkim=s; aspf=s"
    if dmarc_rua:
        dmarc += f"; rua=mailto:{dmarc_rua}"
    return [
        Record(domain, "MX", f"{mail_host}.", priority=10),
        Record(domain, "TXT", spf),
        Record(f"{selector}._domainkey.{domain}", "TXT", dkim_value),
        Record(f"_dmarc.{domain}", "TXT", dmarc),
    ]
