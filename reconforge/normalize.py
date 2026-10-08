"""Merge partial assets from many collectors into one surface per host."""

from __future__ import annotations

from .models import Asset, Port


def _merge_ports(existing: list[Port], incoming: list[Port]) -> list[Port]:
    by_number: dict[int, Port] = {p.number: p for p in existing}
    for p in incoming:
        by_number.setdefault(p.number, p)  # first source wins the label
    return [by_number[n] for n in sorted(by_number)]


def _merge_into(base: Asset, other: Asset) -> None:
    base.ips = sorted(set(base.ips) | set(other.ips))
    base.ports = _merge_ports(base.ports, other.ports)
    base.technologies = sorted(set(base.technologies) | set(other.technologies))
    base.tls_issues = sorted(set(base.tls_issues) | set(other.tls_issues))
    base.tags = sorted(set(base.tags) | set(other.tags))
    base.sources |= other.sources


def normalize(assets: list[Asset]) -> list[Asset]:
    """Combine assets that share a host into one, deduplicating every field."""
    merged: dict[str, Asset] = {}
    for asset in assets:
        if asset.host not in merged:
            merged[asset.host] = Asset(host=asset.host)
        _merge_into(merged[asset.host], asset)
    return [merged[h] for h in sorted(merged)]
