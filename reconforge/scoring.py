"""Deterministic, explainable exposure scoring.

Each rule adds a weight and a human-readable reason to an asset's exposure; the
total maps to a severity level. The rules encode ordinary attack-surface
judgement — remote-admin and database ports open to the internet, TLS problems,
end-of-life software, exposed admin panels — so a score always comes with the
specific reasons behind it, never a bare number.
"""

from __future__ import annotations

from .models import Asset, AssetExposure, ExposureFinding, Severity

# port -> (weight, severity, reason)
_PORT_RULES: dict[int, tuple[int, Severity, str]] = {
    3389: (4, Severity.HIGH, "RDP (3389) exposed to the internet"),
    23: (4, Severity.HIGH, "Telnet (23) exposed — cleartext remote access"),
    445: (3, Severity.HIGH, "SMB (445) exposed to the internet"),
    3306: (3, Severity.HIGH, "MySQL (3306) directly exposed"),
    5432: (3, Severity.HIGH, "PostgreSQL (5432) directly exposed"),
    27017: (3, Severity.HIGH, "MongoDB (27017) directly exposed"),
    6379: (3, Severity.HIGH, "Redis (6379) directly exposed"),
    21: (2, Severity.MEDIUM, "FTP (21) exposed — often cleartext"),
    22: (1, Severity.LOW, "SSH (22) exposed"),
}

_TLS_RULES: dict[str, tuple[int, Severity, str]] = {
    "expired_certificate": (3, Severity.HIGH, "TLS certificate expired"),
    "self_signed_certificate": (2, Severity.MEDIUM, "TLS certificate self-signed"),
    "legacy_tls_1_0": (2, Severity.MEDIUM, "legacy TLS 1.0 supported"),
}

# Substrings marking end-of-life or known-risky software.
_RISKY_TECH = {
    "apache/2.4.49": "Apache 2.4.49 (path traversal CVE-2021-41773)",
    "php/7.2": "PHP 7.2 (end of life)",
    "iis/8.5": "IIS 8.5 (legacy)",
    "openssl/1.0": "OpenSSL 1.0 (end of life)",
}

_LEVELS = [(12, Severity.CRITICAL), (8, Severity.HIGH), (4, Severity.MEDIUM), (1, Severity.LOW)]

# A threshold ladder: (minimum score, level), highest first; below the last one the
# level is INFO. The port/TLS/tech rules use ``_LEVELS``; a calibrated model (see
# ``severity_model``) supplies its own ladder on its own score scale.
LevelLadder = list[tuple[float, Severity]]


def level_for(score: float, levels: LevelLadder = _LEVELS) -> Severity:
    """Map a numeric exposure score to a severity level by threshold."""
    for threshold, level in levels:
        if score >= threshold:
            return level
    return Severity.INFO


def aggregate(
    host: str, findings: list[ExposureFinding], levels: LevelLadder = _LEVELS
) -> AssetExposure:
    """The scoring core: exposure is the sum of finding weights, mapped to a level.

    Every point in the score is one explicit finding, so an ``AssetExposure`` is
    always decomposable into the reasons behind it. Both the built-in rule set and
    the calibrated severity model score through this one function.
    """
    score = sum(f.weight for f in findings)
    return AssetExposure(host=host, score=score, level=level_for(score, levels), findings=findings)


# Retained for backward compatibility with callers of the private helper.
def _level(score: float) -> Severity:
    return level_for(score, _LEVELS)


def score_asset(asset: Asset) -> AssetExposure:
    findings: list[ExposureFinding] = []

    for port in sorted(asset.open_ports()):
        if port in _PORT_RULES:
            weight, severity, reason = _PORT_RULES[port]
            findings.append(ExposureFinding(reason=reason, severity=severity, weight=weight))

    # HTTP served without HTTPS alongside it.
    ports = asset.open_ports()
    if 80 in ports and 443 not in ports:
        findings.append(ExposureFinding("HTTP served without HTTPS", Severity.MEDIUM, 2))

    for issue in asset.tls_issues:
        if issue in _TLS_RULES:
            weight, severity, reason = _TLS_RULES[issue]
            findings.append(ExposureFinding(reason, severity, weight))

    for tech in asset.technologies:
        key = tech.lower()
        for marker, reason in _RISKY_TECH.items():
            if marker in key:
                findings.append(
                    ExposureFinding(f"end-of-life software: {reason}", Severity.HIGH, 2)
                )

    if "admin-panel" in asset.tags:
        findings.append(ExposureFinding("administrative panel exposed", Severity.HIGH, 3))

    return aggregate(asset.host, findings)
