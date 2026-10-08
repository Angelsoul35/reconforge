# ADR 0002: Offline, deterministic collectors by default

## Status

Accepted.

## Context

A recon tool acts on networks, and scanning a host you are not authorised to test
is at best rude and at worst illegal. A tool that performs active scans the
moment it runs invites misuse, and it also makes development painful: tests would
depend on the network, on third parties' systems being up, and on
non-deterministic results.

## Decision

Ship **offline, deterministic** collectors as the default. Each derives a
plausible attack surface from a SHA-256 hash of the target, so the same target
always produces the same assets, and no real host is contacted. Real,
network-touching collectors are an explicit opt-in: they are a separate
implementation of the `Collector` Protocol, and a configuration flag
(`RF_ALLOW_ACTIVE_SCAN`) documents the intent to use them.

## Consequences

- **Safe by default.** Running the tool, the demo, or the tests scans nobody.
- **Deterministic tests and demos.** A hash-seeded surface is reproducible, so
  tests assert concrete outcomes and the demo always shows the same report.
- **Clear authorisation boundary.** Active scanning is a deliberate choice a
  deployment makes with permission, not an accident of running the tool.
- **Trade-off.** The bundled surface is synthetic, so it demonstrates the
  pipeline rather than real findings. That is the correct default for a published
  security tool; the Protocol makes swapping in authorised real collectors a small
  step, and the scoring and normalisation they feed are identical.
