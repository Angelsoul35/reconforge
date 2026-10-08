# ADR 0003: Rule-based, decomposable exposure scoring

## Status

Accepted.

## Context

Each asset needs an exposure score so the report can be ranked and triaged. The
score could be learned (train a model on labelled surfaces) or computed from
rules. Attack-surface risk, though, is well-understood domain knowledge — an
exposed RDP port, an expired certificate, end-of-life software are known-bad
regardless of any dataset — and a security finding must be explainable to the
team that has to act on it.

## Decision

Score with a **weighted rule set**: each rule (an open sensitive port, a TLS
issue, risky software, an exposed admin panel) contributes a weight and a
human-readable `ExposureFinding`. The asset's score is the sum, and the total maps
to a severity level by fixed thresholds. The weights and thresholds are plain
data.

## Consequences

- **Every score is decomposable.** A host's score is exactly the list of findings
  behind it; nothing is a black box, which is essential for a security report.
- **No training data needed, no drift.** The rules encode durable judgement and do
  not degrade as data shifts.
- **Tunable per organisation.** Weights and thresholds are edited to match a risk
  model without retraining anything.
- **Consistent ranking.** The same surface always ranks the same way, so results
  are reproducible and comparable over time.
- **Trade-off.** Rules only catch what they encode; a novel exposure pattern needs
  a new rule. That is acceptable and even desirable here — a new risk should be a
  reviewed, explicit rule, not an opaque inference — and it mirrors the
  learning-vs-policy split used elsewhere in the portfolio (pqrs-router), where
  judgement with consequences is kept deterministic.
