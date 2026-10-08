# ADR 0004: Normalise to one asset per host before scoring

## Status

Accepted.

## Context

Multiple collectors report on the same host: the port scanner and the TLS probe
both describe `www.example.com`. If scoring ran over the raw collector output,
the same host would be scored several times, its exposure split across fragments,
and the report would double-count and mislead. The ranking would be wrong.

## Decision

Insert a **normalisation** step between collection and scoring. Assets that share
a host are merged into a single `Asset`: ports deduplicated by number,
technologies / TLS issues / tags / source labels unioned. Scoring then runs once
per host over the complete picture.

## Consequences

- **Correct, whole-host scoring.** Each host is scored once, over everything known
  about it, so the exposure and the ranking are right.
- **Deduplication.** The same port reported by two collectors counts once; the
  first source keeps the service label.
- **Order-independent.** Merging is commutative over fields (set unions, keyed
  dedup), so the result does not depend on collector order.
- **Provenance kept.** The merged asset records all contributing `sources`.
- **Trade-off.** Merging strictly by host treats two services on different ports
  of the same host as one asset, which is the right granularity for surface
  scoring; per-service findings are still itemised within the host's exposure, so
  no detail is lost.
