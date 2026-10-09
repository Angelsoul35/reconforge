from __future__ import annotations

from reconforge.real_benchmark import derive_verdict


def test_engine_beats_baseline_on_heldout(benchmark_result):
    r = benchmark_result
    # The calibrated reconforge engine must clear the majority baseline on data it
    # never saw, by a wide margin, on both accuracy and macro-F1.
    assert r.heldout_accuracy > r.baseline_accuracy + 0.15
    assert r.heldout_macro_f1 > r.baseline_macro_f1 + 0.20


def test_cross_validation_agrees_with_heldout(benchmark_result):
    r = benchmark_result
    # Low-variance, generalizing engine: CV mean and held-out agree, folds are tight.
    assert abs(r.cv_mean - r.heldout_macro_f1) < 0.10
    assert r.cv_std < 0.05
    # No memorisation: the train/held-out gap is narrow.
    assert r.train_macro_f1 - r.heldout_macro_f1 < 0.10


def test_negative_controls_collapse_to_chance(benchmark_result):
    r = benchmark_result
    # Breaking the feature->label link must destroy performance.
    assert r.control_shuffled_macro_f1 < 0.35
    assert r.control_scrambled_macro_f1 < 0.35
    assert r.control_shuffled_macro_f1 < r.heldout_macro_f1 - 0.25
    assert r.control_scrambled_macro_f1 < r.heldout_macro_f1 - 0.25


def test_base_score_tracks_cvss_closely(benchmark_result):
    # The additive engine approximates the nonlinear CVSS score to a fraction of a
    # point on the 0-10 scale — real signal, not a perfect (nonlinear) match.
    assert benchmark_result.base_score_mae < 0.75
    assert benchmark_result.base_score_mae > 0.0


def test_verdict_is_well_fit_on_real_data(benchmark_result):
    assert benchmark_result.verdict.label == "well-fit"


def test_verdict_logic_discriminates(benchmark_result):
    r = benchmark_result
    # Feeding a collapsed-control score in as the held-out result must NOT be judged
    # well-fit — otherwise the verdict would rubber-stamp noise.
    control = max(r.control_shuffled_macro_f1, r.control_scrambled_macro_f1)
    verdict = derive_verdict(
        baseline_f1=r.baseline_macro_f1,
        cv_mean=control,
        cv_std=r.cv_std,
        train_f1=control,
        heldout_f1=control,
    )
    assert verdict.label != "well-fit"
    assert verdict.label == "underfit"


def test_distribution_spans_classes(benchmark_result):
    # A real NVD sample, not a single-class artifact.
    nonzero = {k for k, v in benchmark_result.distribution.items() if v > 0}
    assert {"low", "medium", "high", "critical"} <= nonzero
