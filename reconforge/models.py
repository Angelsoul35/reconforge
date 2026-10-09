"""The common data model all collectors normalise into.

Recon tools each speak their own format; reconforge maps every finding onto one
small vocabulary — an :class:`Asset` (a host and what is known about it) built
from :class:`Port`, technology strings, TLS issues and tags — so findings from
different sources merge cleanly and are scored by one set of rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Port:
    number: int
    service: str
    source: str = ""


@dataclass
class Asset:
    host: str
    ips: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    tls_issues: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)

    def open_ports(self) -> set[int]:
        return {p.number for p in self.ports}


@dataclass
class ExposureFinding:
    reason: str
    severity: Severity
    weight: float  # integer rule weights, or calibrated real weights (see severity_model)


@dataclass
class AssetExposure:
    host: str
    score: float
    level: Severity
    findings: list[ExposureFinding] = field(default_factory=list)
