from __future__ import annotations

from reconforge.collectors import (
    PortCollector,
    SubdomainCollector,
    TechCollector,
    default_collectors,
)
from reconforge.models import Asset, Port
from reconforge.normalize import normalize


def test_subdomain_collector_includes_apex_and_is_deterministic():
    c = SubdomainCollector()
    first = c.collect("example.com")
    second = c.collect("example.com")
    hosts = {a.host for a in first}
    assert "example.com" in hosts
    assert {a.host for a in second} == hosts  # deterministic
    assert any(a.host.endswith(".example.com") for a in first)


def test_port_collector_reports_common_ports():
    ports = PortCollector().collect("host.example.com")[0].open_ports()
    assert {22, 80, 443} <= ports


def test_tech_collector_deterministic():
    a = TechCollector().collect("api.example.com")[0]
    b = TechCollector().collect("api.example.com")[0]
    assert a.technologies == b.technologies and a.technologies


def test_default_collectors_present():
    assert {c.name for c in default_collectors()} == {"subdomains", "ports", "tech", "tls"}


def test_normalize_merges_and_dedups():
    a1 = Asset(host="h", ports=[Port(80, "http", "ports")], technologies=["nginx"], sources={"a"})
    a2 = Asset(
        host="h",
        ports=[Port(80, "http", "x"), Port(443, "https", "ports")],
        technologies=["nginx", "php"],
        sources={"b"},
    )
    merged = normalize([a1, a2])
    assert len(merged) == 1
    asset = merged[0]
    assert asset.open_ports() == {80, 443}  # 80 not duplicated
    assert sorted(asset.technologies) == ["nginx", "php"]
    assert asset.sources == {"a", "b"}
