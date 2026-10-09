"""Validate reconforge's scoring engine against the real CVSS severity standard.

This harness calibrates reconforge's weighted-finding engine on real NVD/CVSS
records and measures whether it generalizes — not whether it can memorise:

* a **majority-class baseline** to beat;
* **stratified k-fold cross-validation** on the training split (mean +/- std);
* a **held-out test set** never seen during calibration;
* the **train vs held-out gap**;
* two **negative controls** (shuffled labels, scrambled inputs) that must collapse
  to chance;
* an explicit **verdict** (well-fit / overfit / underfit) derived from whether the
  cross-validation and held-out scores agree and clear the baseline.

Everything runs through :class:`reconforge.severity_model.CalibratedSeverityModel`,
which scores via :func:`reconforge.scoring.aggregate` — the same engine the port /
TLS / tech rules use.

The gold label is a deterministic function of a record's own metrics (the CVSS
formula), so the controls decouple the stored (score, label) arrays from the
records they describe: that is the only way to sever the feature->label link and
show the engine is learning real structure, not an artifact of the pipeline.
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, replace

from .models import Severity
from .real_data import CvssRecord, cvss_base_score, gold_severity, load_cvss_dataset
from .severity_model import METRIC_DOMAINS, CalibratedSeverityModel

LABELS: list[Severity] = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]

_METRIC_ATTRS = ("av", "ac", "pr", "ui", "scope", "conf", "integ", "avail")


# --- metrics -----------------------------------------------------------------


def accuracy(y_true: list[Severity], y_pred: list[Severity]) -> float:
    if not y_true:
        return 0.0
    return sum(1 for a, b in zip(y_true, y_pred, strict=True) if a == b) / len(y_true)


def per_class_f1(y_true: list[Severity], y_pred: list[Severity]) -> dict[Severity, float]:
    out: dict[Severity, float] = {}
    for label in LABELS:
        tp = sum(1 for a, b in zip(y_true, y_pred, strict=True) if a == label and b == label)
        fp = sum(1 for a, b in zip(y_true, y_pred, strict=True) if a != label and b == label)
        fn = sum(1 for a, b in zip(y_true, y_pred, strict=True) if a == label and b != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        out[label] = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return out


def macro_f1(y_true: list[Severity], y_pred: list[Severity]) -> float:
    scores = per_class_f1(y_true, y_pred)
    # Average only over classes present in the truth, so a label absent from a
    # fold does not drag the mean down with a spurious zero.
    present = [label for label in LABELS if any(a == label for a in y_true)]
    if not present:
        return 0.0
    return sum(scores[label] for label in present) / len(present)


# --- splitting ---------------------------------------------------------------


def _stratified_buckets(labels: list[Severity], seed: int) -> list[list[int]]:
    rng = random.Random(seed)
    buckets: dict[Severity, list[int]] = {}
    for idx, label in enumerate(labels):
        buckets.setdefault(label, []).append(idx)
    ordered = [buckets[label] for label in LABELS if label in buckets]
    for indices in ordered:
        rng.shuffle(indices)
    return ordered


def stratified_split(
    labels: list[Severity], test_frac: float, seed: int
) -> tuple[list[int], list[int]]:
    """Split indices into (train, test), preserving each class's proportion."""
    train: list[int] = []
    test: list[int] = []
    for indices in _stratified_buckets(labels, seed):
        cut = int(round(len(indices) * test_frac))
        test.extend(indices[:cut])
        train.extend(indices[cut:])
    return train, test


def stratified_folds(labels: list[Severity], k: int, seed: int) -> list[list[int]]:
    """Partition indices into ``k`` stratified folds."""
    folds: list[list[int]] = [[] for _ in range(k)]
    for indices in _stratified_buckets(labels, seed):
        for position, idx in enumerate(indices):
            folds[position % k].append(idx)
    return folds


# --- the labelled dataset ----------------------------------------------------


@dataclass
class Dataset:
    """Parallel arrays: a record, its CVSS base score, and its gold severity.

    Keeping score and label as stored arrays (rather than recomputing them from a
    record on demand) is what lets the negative controls break the link between a
    record's features and its target.
    """

    records: list[CvssRecord]
    scores: list[float]
    golds: list[Severity]

    @classmethod
    def build(cls, records: list[CvssRecord]) -> Dataset:
        scores = [cvss_base_score(rec) or 0.0 for rec in records]
        golds = [gold_severity(rec) for rec in records]
        return cls(records, scores, golds)

    def subset(self, idx: list[int]) -> Dataset:
        return Dataset(
            [self.records[i] for i in idx],
            [self.scores[i] for i in idx],
            [self.golds[i] for i in idx],
        )

    def __len__(self) -> int:
        return len(self.records)


def fit_model(data: Dataset) -> CalibratedSeverityModel:
    return CalibratedSeverityModel.fit(data.records, data.scores)


def evaluate(model: CalibratedSeverityModel, data: Dataset) -> tuple[float, float, list[Severity]]:
    preds = [model.predict(rec) for rec in data.records]
    return accuracy(data.golds, preds), macro_f1(data.golds, preds), preds


def cross_validate(data: Dataset, k: int, seed: int) -> list[float]:
    """Stratified k-fold macro-F1 (one score per fold)."""
    folds = stratified_folds(data.golds, k, seed)
    scores: list[float] = []
    for i in range(k):
        val_idx = folds[i]
        val_set = set(val_idx)
        train_idx = [j for j in range(len(data)) if j not in val_set]
        model = fit_model(data.subset(train_idx))
        _, f1, _ = evaluate(model, data.subset(val_idx))
        scores.append(f1)
    return scores


# --- negative controls -------------------------------------------------------


def shuffle_labels(data: Dataset, seed: int) -> Dataset:
    """Permute the (score, gold) arrays against the records: features now predict
    an unrelated target, so a model that learned real structure must collapse."""
    rng = random.Random(seed)
    order = list(range(len(data)))
    rng.shuffle(order)
    return Dataset(
        list(data.records),
        [data.scores[j] for j in order],
        [data.golds[j] for j in order],
    )


def scramble_inputs(data: Dataset, seed: int) -> Dataset:
    """Permute each metric column of the records independently, keeping the stored
    (score, gold) aligned to the original rows: the joint feature structure is
    destroyed while the labels stay put, so prediction must collapse to chance."""
    rng = random.Random(seed)
    columns = {attr: [getattr(rec, attr) for rec in data.records] for attr in _METRIC_ATTRS}
    for attr in columns:
        rng.shuffle(columns[attr])
    scrambled = [
        replace(rec, **{attr: columns[attr][i] for attr in _METRIC_ATTRS})
        for i, rec in enumerate(data.records)
    ]
    return Dataset(scrambled, list(data.scores), list(data.golds))


# --- verdict -----------------------------------------------------------------


@dataclass
class Verdict:
    label: str
    rationale: str


def derive_verdict(
    *,
    baseline_f1: float,
    cv_mean: float,
    cv_std: float,
    train_f1: float,
    heldout_f1: float,
) -> Verdict:
    """Judge fit by CV<->held-out agreement and the margin over the baseline.

    A saturating-but-stable engine is well-fit; a wide train/held-out gap with
    held-out well below CV is overfit; no real margin over the baseline (as in the
    negative controls) is underfit.
    """
    margin = heldout_f1 - baseline_f1
    gap = train_f1 - heldout_f1
    agreement = abs(cv_mean - heldout_f1)
    has_signal = heldout_f1 >= baseline_f1 + 0.10 and heldout_f1 >= 1.5 * max(baseline_f1, 1e-9)

    if not has_signal:
        return Verdict(
            "underfit",
            f"held-out macro-F1 {heldout_f1:.3f} does not clear the baseline "
            f"{baseline_f1:.3f} by a real margin (margin {margin:+.3f}) — no learnable "
            "signal, as expected for a collapsed control.",
        )
    if gap > 0.10 and heldout_f1 < cv_mean - 2 * cv_std:
        return Verdict(
            "overfit",
            f"train macro-F1 {train_f1:.3f} exceeds held-out {heldout_f1:.3f} by "
            f"{gap:.3f} and held-out sits below CV {cv_mean:.3f}-2sd — memorisation.",
        )
    return Verdict(
        "well-fit",
        f"held-out macro-F1 {heldout_f1:.3f} clears the baseline {baseline_f1:.3f} "
        f"(margin {margin:+.3f}); CV {cv_mean:.3f}+/-{cv_std:.3f} agrees with held-out "
        f"(|diff| {agreement:.3f}); train/held-out gap {gap:+.3f} is narrow.",
    )


# --- orchestration -----------------------------------------------------------


@dataclass
class BenchmarkResult:
    n_records: int
    distribution: dict[str, int]
    majority_label: str
    baseline_accuracy: float
    baseline_macro_f1: float
    cv_scores: list[float]
    cv_mean: float
    cv_std: float
    train_accuracy: float
    train_macro_f1: float
    heldout_accuracy: float
    heldout_macro_f1: float
    heldout_per_class_f1: dict[str, float]
    base_score_mae: float
    control_shuffled_macro_f1: float
    control_scrambled_macro_f1: float
    verdict: Verdict


def run_benchmark(
    records: list[CvssRecord] | None = None,
    *,
    k: int = 5,
    test_frac: float = 0.2,
    seed: int = 0,
) -> BenchmarkResult:
    records = records if records is not None else load_cvss_dataset()
    data = Dataset.build(records)

    train_idx, test_idx = stratified_split(data.golds, test_frac, seed)
    train = data.subset(train_idx)
    test = data.subset(test_idx)

    # Baseline: always predict the training-majority class.
    counts: dict[Severity, int] = {}
    for level in train.golds:
        counts[level] = counts.get(level, 0) + 1
    majority = max(counts, key=lambda s: counts[s])
    baseline_pred = [majority] * len(test)
    baseline_acc = accuracy(test.golds, baseline_pred)
    baseline_f1 = macro_f1(test.golds, baseline_pred)

    # Cross-validation on the training split only.
    cv_scores = cross_validate(train, k, seed)
    cv_mean = statistics.mean(cv_scores)
    cv_std = statistics.pstdev(cv_scores)

    # Calibrate on the full training split; evaluate on train and held-out test.
    model = fit_model(train)
    train_acc, train_f1, _ = evaluate(model, train)
    heldout_acc, heldout_f1, heldout_pred = evaluate(model, test)

    # How closely does the additive engine track the real CVSS base score?
    mae = statistics.mean(
        abs(model.predicted_score(rec) - score)
        for rec, score in zip(test.records, test.scores, strict=True)
    )

    # Negative controls: break the feature->label link; performance must collapse.
    shuffled = shuffle_labels(data, seed)
    control_shuffled_f1 = evaluate(
        fit_model(shuffled.subset(train_idx)), shuffled.subset(test_idx)
    )[1]
    scrambled = scramble_inputs(data, seed + 1)
    control_scrambled_f1 = evaluate(
        fit_model(scrambled.subset(train_idx)), scrambled.subset(test_idx)
    )[1]

    verdict = derive_verdict(
        baseline_f1=baseline_f1,
        cv_mean=cv_mean,
        cv_std=cv_std,
        train_f1=train_f1,
        heldout_f1=heldout_f1,
    )

    distribution: dict[str, int] = {}
    for level in data.golds:
        distribution[level.value] = distribution.get(level.value, 0) + 1

    return BenchmarkResult(
        n_records=len(data),
        distribution=distribution,
        majority_label=majority.value,
        baseline_accuracy=baseline_acc,
        baseline_macro_f1=baseline_f1,
        cv_scores=cv_scores,
        cv_mean=cv_mean,
        cv_std=cv_std,
        train_accuracy=train_acc,
        train_macro_f1=train_f1,
        heldout_accuracy=heldout_acc,
        heldout_macro_f1=heldout_f1,
        heldout_per_class_f1={
            lvl.value: f1 for lvl, f1 in per_class_f1(test.golds, heldout_pred).items()
        },
        base_score_mae=mae,
        control_shuffled_macro_f1=control_shuffled_f1,
        control_scrambled_macro_f1=control_scrambled_f1,
        verdict=verdict,
    )


def format_report(result: BenchmarkResult) -> str:
    lines: list[str] = []
    add = lines.append
    add("reconforge severity engine vs the CVSS v3.1 standard (real NVD data)")
    add("=" * 70)
    add(f"records (valid CVSS v3.1 gold label): {result.n_records}")
    add("gold severity distribution:")
    total = sum(result.distribution.values())
    for level in LABELS:
        count = result.distribution.get(level.value, 0)
        add(f"    {level.value:9s} {count:6d}  {count / total:.3f}")
    add("")
    add(
        f"metric vocabulary: {sum(len(v) for v in METRIC_DOMAINS.values())} values "
        f"across {len(METRIC_DOMAINS)} CVSS metrics"
    )
    add("")
    add(
        f"majority baseline ({result.majority_label}): "
        f"acc={result.baseline_accuracy:.3f}  macro-F1={result.baseline_macro_f1:.3f}"
    )
    add(
        f"cross-validation macro-F1 (k={len(result.cv_scores)}): "
        f"{result.cv_mean:.3f} +/- {result.cv_std:.3f}  "
        f"folds={[round(s, 3) for s in result.cv_scores]}"
    )
    add(f"train:    acc={result.train_accuracy:.3f}  macro-F1={result.train_macro_f1:.3f}")
    add(f"held-out: acc={result.heldout_accuracy:.3f}  macro-F1={result.heldout_macro_f1:.3f}")
    add(f"train vs held-out macro-F1 gap: {result.train_macro_f1 - result.heldout_macro_f1:+.3f}")
    add(f"base-score MAE on held-out (0-10 scale): {result.base_score_mae:.3f}")
    add("held-out per-class F1:")
    for level in LABELS:
        add(f"    {level.value:9s} {result.heldout_per_class_f1.get(level.value, 0.0):.3f}")
    add("")
    add("negative controls (must collapse to chance):")
    add(f"    shuffled labels : macro-F1={result.control_shuffled_macro_f1:.3f}")
    add(f"    scrambled inputs: macro-F1={result.control_scrambled_macro_f1:.3f}")
    add("")
    add(f"VERDICT: {result.verdict.label.upper()}")
    add(f"    {result.verdict.rationale}")
    return "\n".join(lines)


def main() -> None:
    print(format_report(run_benchmark()))


if __name__ == "__main__":
    main()
