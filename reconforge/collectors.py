"""Pluggable recon collectors behind one interface.

A :class:`Collector` takes a target and returns partial :class:`Asset` records.
Real deployments implement this Protocol over DNS, a port scanner, an HTTP
fingerprinter, a TLS probe, or a passive source like certificate transparency.
The collectors here are **offline and deterministic**: they derive a plausible,
repeatable surface from a seed of the target so the tool runs end to end with no
network and no scanning of anyone — which is also what the tests use.

Only ever point real collectors at systems you are authorised to assess.
"""

from __future__ import annotations

import hashlib
from typing import Protocol, runtime_checkable

from .models import Asset, Port

# Service names by well-known port, for labelling synthetic findings.
_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    27017: "mongodb",
}


def _rng(seed_text: str) -> int:
    return int(hashlib.sha256(seed_text.encode()).hexdigest(), 16)


@runtime_checkable
class Collector(Protocol):
    name: str

    def collect(self, target: str) -> list[Asset]: ...


class SubdomainCollector:
    """Discovers hostnames under the target domain (passive-style)."""

    name = "subdomains"
    _CANDIDATES = ["www", "api", "mail", "dev", "staging", "admin", "vpn", "db", "legacy"]

    def collect(self, target: str) -> list[Asset]:
        assets: list[Asset] = [Asset(host=target, sources={self.name})]
        for sub in self._CANDIDATES:
            if _rng(f"{target}:{sub}") % 3 != 0:  # ~2/3 of candidates "exist"
                host = f"{sub}.{target}"
                octet = _rng(host) % 254 + 1
                assets.append(Asset(host=host, ips=[f"203.0.113.{octet}"], sources={self.name}))
        return assets


class PortCollector:
    """Reports open ports per host (scanner-style)."""

    name = "ports"
    _COMMON = [22, 80, 443]
    _EXTRA = [21, 23, 445, 3306, 3389, 5432, 6379, 8080, 27017]

    def collect(self, target: str) -> list[Asset]:
        # A single host's open ports; the service composes this across hosts.
        ports = [Port(p, _SERVICES.get(p, "unknown"), self.name) for p in self._COMMON]
        for p in self._EXTRA:
            if _rng(f"{target}:port:{p}") % 4 == 0:  # ~1/4 chance an extra port is open
                ports.append(Port(p, _SERVICES.get(p, "unknown"), self.name))
        return [Asset(host=target, ports=ports, sources={self.name})]


class TechCollector:
    """Fingerprints server technologies (banner-style)."""

    name = "tech"
    _STACKS = [
        ["nginx/1.25", "react"],
        ["Apache/2.4.49", "php/7.2"],  # old, known-risky
        ["openssh/9.6", "ubuntu"],
        ["IIS/8.5", "asp.net"],  # old
        ["nginx/1.25", "node"],
    ]

    def collect(self, target: str) -> list[Asset]:
        stack = self._STACKS[_rng(f"{target}:tech") % len(self._STACKS)]
        tags = ["admin-panel"] if target.startswith("admin.") else []
        return [Asset(host=target, technologies=list(stack), tags=tags, sources={self.name})]


class TLSCollector:
    """Checks the TLS posture of a host (probe-style)."""

    name = "tls"

    def collect(self, target: str) -> list[Asset]:
        issues: list[str] = []
        r = _rng(f"{target}:tls")
        if r % 5 == 0:
            issues.append("expired_certificate")
        if r % 7 == 0:
            issues.append("self_signed_certificate")
        if r % 6 == 0:
            issues.append("legacy_tls_1_0")
        return [Asset(host=target, tls_issues=issues, sources={self.name})]


def default_collectors() -> list[Collector]:
    return [SubdomainCollector(), PortCollector(), TechCollector(), TLSCollector()]
