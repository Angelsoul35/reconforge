"""A calibrated severity model built on reconforge's own scoring engine.

reconforge's production rules score port/TLS/tech exposures with hand-set integer
weights. Its README notes those weights are "plain data and easy to tune to an
organisation's risk model". This module takes that idea to a real corpus: it keeps
reconforge's engine — a weighted set of explainable findings summed into a score
and mapped to a severity level by :func:`reconforge.scoring.aggregate` — but
*calibrates* the weights to a large body of real vulnerabilities (NVD/CVSS) so the
engine reproduces the authoritative CVSS v3.1 severity.

The model is deliberately additive and interpretable: one weight per CVSS metric
value, fit by least squares to the real base scores. Each prediction decomposes
into per-metric contributions, exactly like a port-exposure score decomposes into
its findings. CVSS's exploitability term is multiplicative, so a purely additive
engine approximates it; the benchmark measures that residual directly and reports
it as a concrete bias term with a clear path to close it (add pairwise interaction
findings), rather than hiding behind a rounder number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import AssetExposure, ExposureFinding, Severity
from .real_data import CVSS_BANDS, CvssRecord
from .scoring import aggregate

# The fixed CVSS v3.1 metric vocabulary (name -> ordered possible values). Fixing
# it (rather than reading it off the training split) means an unseen combination
# never breaks prediction, and every fold shares one feature space.
METRIC_DOMAINS: dict[str, tuple[str, ...]] = {
    "AV": ("Network", "Adjacent Network", "Local", "Physical"),
    "AC": ("Low", "High"),
    "PR": ("None", "Low", "High"),
    "UI": ("None", "Required"),
    "S": ("Unchanged", "Changed"),
    "C": ("High", "Low", "None"),
    "I": ("High", "Low", "None"),
    "A": ("High", "Low", "None"),
}

# A readable gloss for each metric, used in finding reasons.
_METRIC_LABEL = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality impact",
    "I": "Integrity impact",
    "A": "Availability impact",
}

_FEATURES: list[tuple[str, str]] = [
    (metric, value) for metric, values in METRIC_DOMAINS.items() for value in values
]
_FEATURE_INDEX: dict[tuple[str, str], int] = {f: i for i, f in enumerate(_FEATURES)}
_INTERCEPT = len(_FEATURES)
_N_PARAMS = _INTERCEPT + 1


def _severity_for_weight(weight: float) -> Severity:
    """A coarse severity for one metric's contribution, for the explainable report."""
    if weight >= 2.0:
        return Severity.HIGH
    if weight >= 1.0:
        return Severity.MEDIUM
    if weight > 0.0:
        return Severity.LOW
    return Severity.INFO


def _solve(normal: list[list[float]], rhs: list[float]) -> list[float]:
    """Solve ``normal @ w = rhs`` by Gaussian elimination with partial pivoting."""
    n = len(rhs)
    mat = [normal[r][:] + [rhs[r]] for r in range(n)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(mat[r][col]))
        mat[col], mat[pivot] = mat[pivot], mat[col]
        pivot_value = mat[col][col]
        if abs(pivot_value) < 1e-12:
            continue
        for r in range(n):
            if r != col and mat[r][col] != 0.0:
                factor = mat[r][col] / pivot_value
                for k in range(col, n + 1):
                    mat[r][k] -= factor * mat[col][k]
    return [mat[r][n] / mat[r][r] if abs(mat[r][r]) > 1e-12 else 0.0 for r in range(n)]


@dataclass
class CalibratedSeverityModel:
    """reconforge's engine with weights calibrated to the real CVSS corpus."""

    weights: list[float] = field(default_factory=lambda: [0.0] * _N_PARAMS)

    @classmethod
    def fit(
        cls, records: list[CvssRecord], targets: list[float], *, ridge: float = 1e-6
    ) -> CalibratedSeverityModel:
        """Least-squares calibration of per-metric weights to the base scores.

        Exploits the one-hot structure: each record touches only its 8 active
        metric values plus the intercept, so the normal equations are built from
        9x9 blocks rather than a dense pass.
        """
        normal = [[0.0] * _N_PARAMS for _ in range(_N_PARAMS)]
        rhs = [0.0] * _N_PARAMS
        for rec, target in zip(records, targets, strict=True):
            active = _active_indices(rec)
            for a in active:
                rhs[a] += target
                for b in active:
                    normal[a][b] += 1.0
        for i in range(_N_PARAMS):
            normal[i][i] += ridge
        return cls(weights=_solve(normal, rhs))

    def findings(self, rec: CvssRecord) -> list[ExposureFinding]:
        """One explainable finding per metric, plus the fitted base offset."""
        out: list[ExposureFinding] = []
        for metric, value in rec.metrics().items():
            idx = _FEATURE_INDEX.get((metric, value))
            if idx is None:
                continue
            weight = self.weights[idx]
            out.append(
                ExposureFinding(
                    reason=f"{_METRIC_LABEL[metric]}: {value}",
                    severity=_severity_for_weight(weight),
                    weight=weight,
                )
            )
        out.append(
            ExposureFinding(
                reason="calibrated base offset",
                severity=Severity.INFO,
                weight=self.weights[_INTERCEPT],
            )
        )
        return out

    def score(self, rec: CvssRecord) -> AssetExposure:
        """Score a vulnerability through reconforge's own ``aggregate`` engine."""
        return aggregate(rec.cve_id, self.findings(rec), CVSS_BANDS)

    def predict(self, rec: CvssRecord) -> Severity:
        return self.score(rec).level

    def predicted_score(self, rec: CvssRecord) -> float:
        return self.score(rec).score


def _active_indices(rec: CvssRecord) -> list[int]:
    indices = [_INTERCEPT]
    for metric, value in rec.metrics().items():
        idx = _FEATURE_INDEX.get((metric, value))
        if idx is not None:
            indices.append(idx)
    return indices
