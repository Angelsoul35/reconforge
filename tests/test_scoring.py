from __future__ import annotations

from reconforge.models import Asset, Port, Severity
from reconforge.scoring import score_asset


def test_clean_asset_scores_zero():
    asset = Asset(host="h", ports=[Port(443, "https")])
    exposure = score_asset(asset)
    assert exposure.score == 0
    assert exposure.level is Severity.INFO
    assert exposure.findings == []


def test_exposed_admin_host_is_critical():
    asset = Asset(
        host="admin.h",
        ports=[Port(3389, "rdp"), Port(445, "smb"), Port(3306, "mysql")],
        tls_issues=["expired_certificate"],
        tags=["admin-panel"],
    )
    exposure = score_asset(asset)
    assert exposure.level is Severity.CRITICAL  # 4+3+3+3+3 = 16 >= 12
    reasons = " ".join(f.reason for f in exposure.findings)
    assert "RDP" in reasons and "expired" in reasons and "panel" in reasons


def test_http_without_https_flagged():
    exposure = score_asset(Asset(host="h", ports=[Port(80, "http")]))
    assert any("without HTTPS" in f.reason for f in exposure.findings)


def test_end_of_life_software_flagged():
    exposure = score_asset(Asset(host="h", technologies=["Apache/2.4.49"]))
    assert any("end-of-life" in f.reason for f in exposure.findings)


def test_level_thresholds():
    # SSH only (weight 1) -> low.
    assert score_asset(Asset(host="h", ports=[Port(22, "ssh")])).level is Severity.LOW
