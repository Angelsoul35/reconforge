"""Orchestrate discovery, enrichment, normalisation and scoring."""

from __future__ import annotations

from .collectors import (
    Collector,
    PortCollector,
    SubdomainCollector,
    TechCollector,
    TLSCollector,
)
from .config import Settings, get_settings
from .models import Asset, Severity
from .normalize import normalize
from .scoring import score_asset


class ReconService:
    def __init__(
        self,
        settings: Settings | None = None,
        discovery: Collector | None = None,
        host_collectors: list[Collector] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.discovery = discovery or SubdomainCollector()
        self.host_collectors = host_collectors or [
            PortCollector(), TechCollector(), TLSCollector()
        ]

    def gather(self, target: str) -> list[Asset]:
        # 1) discover hosts, 2) enrich each host, 3) normalise per host.
        found = self.discovery.collect(target)
        all_assets: list[Asset] = list(found)
        for host_asset in found:
            for collector in self.host_collectors:
                all_assets.extend(collector.collect(host_asset.host))
        return normalize(all_assets)

    def assess(self, target: str) -> dict:
        assets = self.gather(target)
        exposures = [score_asset(a) for a in assets]
        exposures.sort(key=lambda e: e.score, reverse=True)

        by_level: dict[str, int] = {level.value: 0 for level in Severity}
        for e in exposures:
            by_level[e.level.value] += 1

        return {
            "target": target,
            "asset_count": len(assets),
            "surface_score": sum(e.score for e in exposures),
            "by_level": by_level,
            "assets": [
                {
                    "host": e.host,
                    "score": e.score,
                    "level": e.level.value,
                    "findings": [
                        {"reason": f.reason, "severity": f.severity.value, "weight": f.weight}
                        for f in e.findings
                    ],
                }
                for e in exposures
            ],
        }
