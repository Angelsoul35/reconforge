from __future__ import annotations

import json

import pytest

from reconforge import real_data
from reconforge.models import Severity
from reconforge.real_data import (
    CvssRecord,
    cvss_base_score,
    fetch_cvss_rows,
    gold_severity,
    load_cvss_dataset,
)
from reconforge.severity_model import METRIC_DOMAINS

# A real, well-known vector: CVE-style RCE, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 Critical.
_CRITICAL = CvssRecord(
    cve_id="CVE-TEST-CRITICAL",
    av="Network", ac="Low", pr="None", ui="None", scope="Unchanged",
    conf="High", integ="High", avail="High",
)
# AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L -> 3.7 Low (availability-only, hard to exploit).
_LOW = CvssRecord(
    cve_id="CVE-TEST-LOW",
    av="Network", ac="High", pr="None", ui="None", scope="Unchanged",
    conf="None", integ="None", avail="Low",
)


def test_cvss_formula_matches_known_vectors():
    # If the official v3.1 formula is broken, these exact numbers move.
    assert cvss_base_score(_CRITICAL) == pytest.approx(9.8, abs=0.05)
    assert gold_severity(_CRITICAL) is Severity.CRITICAL
    assert cvss_base_score(_LOW) == pytest.approx(3.7, abs=0.05)
    assert gold_severity(_LOW) is Severity.LOW


def test_scope_change_raises_the_score():
    # Scope:Changed applies the 1.08 multiplier and the changed-scope PR weights;
    # the identical impact/exploitability under Changed must score strictly higher.
    unchanged = CvssRecord("u", "Network", "Low", "Low", "None", "Unchanged", "Low", "Low", "None")
    changed = CvssRecord("c", "Network", "Low", "Low", "None", "Changed", "Low", "Low", "None")
    assert cvss_base_score(changed) > cvss_base_score(unchanged)


def test_none_impact_scores_zero_and_maps_to_info():
    rec = CvssRecord("z", "Network", "Low", "None", "None", "Unchanged", "None", "None", "None")
    assert cvss_base_score(rec) == 0.0
    assert gold_severity(rec) is Severity.INFO


def test_loader_returns_real_data_with_expected_shape():
    records = load_cvss_dataset()
    assert len(records) >= 5000  # the vendored snapshot is substantial
    for rec in records[:200]:
        assert rec.cve_id.startswith("CVE")
        assert rec.av in METRIC_DOMAINS["AV"]
        assert rec.conf in METRIC_DOMAINS["C"]
        # Every loaded record must carry a computable gold label.
        assert gold_severity(rec) in {
            Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL
        }


def test_loader_covers_every_severity_band():
    # A real NVD sample spans the whole severity spectrum, not one class.
    present = {gold_severity(rec) for rec in load_cvss_dataset()}
    assert {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL} <= present


# --- the fetch path, monkeypatched offline -----------------------------------


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _payload() -> dict:
    row = {
        "cve_id": "CVE-2024-0001", "date": "2024-01-01",
        "cwe_base_id": 79.0, "cwe_base_name": "CWE-79",
        "cvss_av": "Network", "cvss_ac": "Low", "cvss_pr": "None", "cvss_ui": "None",
        "cvss_s": "Unchanged", "cvss_c": "High", "cvss_i": "High", "cvss_a": "High",
    }
    return {"num_rows_total": 100_000, "rows": [{"row": row}, {"row": row}]}


def test_fetch_retries_then_succeeds():
    calls = {"n": 0}

    def flaky_opener(url: str, timeout: float) -> _FakeResponse:
        calls["n"] += 1
        if calls["n"] <= 2:  # first two attempts fail, third succeeds
            raise ConnectionResetError("transient")
        return _FakeResponse(_payload())

    rows = fetch_cvss_rows(
        n_rows=100, block=100, opener=flaky_opener, retries=4,
        backoff=0.0, pause=0.0, sleep=lambda _s: None,
    )
    # Two induced failures, then success: the first request recovers on its third
    # attempt (calls 1-2 fail, 3 succeeds for the row-count probe), and the data
    # request succeeds on call 4. Without working retries the first failure raises.
    assert calls["n"] == 4
    assert rows and rows[0]["cvss_av"] == "Network"
    assert set(real_data.SNAPSHOT_FIELDS) <= set(rows[0])


def test_fetch_retries_then_exhausts_and_raises():
    calls = {"n": 0}

    def dead_opener(url: str, timeout: float) -> _FakeResponse:
        calls["n"] += 1
        raise TimeoutError("down")

    with pytest.raises(RuntimeError, match="after 3 attempts"):
        fetch_cvss_rows(
            n_rows=100, block=100, opener=dead_opener, retries=3,
            backoff=0.0, pause=0.0, sleep=lambda _s: None,
        )
    assert calls["n"] == 3  # exactly `retries` attempts, then give up


def test_fetch_uses_module_seam_when_no_opener_passed(monkeypatch):
    # The documented seam: monkeypatch real_data.urlopen.
    monkeypatch.setattr(real_data, "urlopen", lambda url, timeout: _FakeResponse(_payload()))
    rows = fetch_cvss_rows(n_rows=100, block=100, pause=0.0, sleep=lambda _s: None)
    assert rows and rows[0]["cve_id"] == "CVE-2024-0001"


def test_fetch_write_and_load_round_trip(tmp_path):
    # End to end offline: fetch (faked) -> write snapshot -> load it back as records.
    rows = fetch_cvss_rows(
        n_rows=100, block=100,
        opener=lambda url, timeout: _FakeResponse(_payload()),
        pause=0.0, sleep=lambda _s: None,
    )
    path = real_data.write_snapshot(rows, tmp_path / "snap.jsonl")
    records = load_cvss_dataset(path)
    assert records and all(isinstance(r, CvssRecord) for r in records)
    assert gold_severity(records[0]) is Severity.CRITICAL  # the faked payload's vector


def test_load_missing_snapshot_raises(tmp_path):
    import pytest as _pytest

    with _pytest.raises(FileNotFoundError, match="regenerate"):
        load_cvss_dataset(tmp_path / "does_not_exist.jsonl")
