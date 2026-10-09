from __future__ import annotations

import statistics

from reconforge.models import Severity
from reconforge.real_data import CVSS_BANDS, CvssRecord, cvss_base_score, severity_for_score
from reconforge.scoring import aggregate
from reconforge.severity_model import CalibratedSeverityModel

_CRITICAL = CvssRecord(
    "crit", "Network", "Low", "None", "None", "Unchanged", "High", "High", "High"
)
_MINIMAL = CvssRecord(
    "min", "Physical", "High", "High", "Required", "Unchanged", "None", "None", "Low"
)


def _fit(records):
    return CalibratedSeverityModel.fit(records, [cvss_base_score(r) or 0.0 for r in records])


def test_model_scores_through_reconforge_aggregate_engine(cvss_records):
    model = _fit(cvss_records[:2000])
    exposure = model.score(_CRITICAL)
    # The engine contract: score is exactly the sum of explainable findings.
    assert exposure.findings
    assert all(f.reason for f in exposure.findings)
    assert exposure.score == sum(f.weight for f in exposure.findings)
    # And the level is exactly what reconforge's aggregate engine assigns.
    assert exposure.level is aggregate(_CRITICAL.cve_id, exposure.findings, CVSS_BANDS).level
    # A reason should name a real CVSS metric value.
    assert any(f.reason == "Attack Vector: Network" for f in exposure.findings)


def test_calibration_learns_severity_ordering(cvss_records):
    model = _fit(cvss_records)
    # A maximal remote RCE must outrank a minimal local, hard-to-exploit issue.
    assert model.predicted_score(_CRITICAL) > model.predicted_score(_MINIMAL)
    assert model.predict(_CRITICAL) is Severity.CRITICAL
    assert model.predict(_MINIMAL) in {Severity.INFO, Severity.LOW}


def test_calibration_beats_predicting_the_mean(cvss_records):
    records = cvss_records
    targets = [cvss_base_score(r) or 0.0 for r in records]
    model = _fit(records)
    mean = statistics.mean(targets)
    model_mae = statistics.mean(
        abs(model.predicted_score(r) - t) for r, t in zip(records, targets, strict=True)
    )
    mean_mae = statistics.mean(abs(mean - t) for t in targets)
    # The calibrated additive engine tracks the real CVSS score far better than a
    # constant; on CVSS v3.1 this lands well under 1 point of error.
    assert model_mae < mean_mae * 0.5
    assert model_mae < 1.0


def test_predicted_level_follows_cvss_bands(cvss_records):
    model = _fit(cvss_records[:2000])
    for rec in (_CRITICAL, _MINIMAL):
        assert model.predict(rec) is severity_for_score(model.predicted_score(rec))
