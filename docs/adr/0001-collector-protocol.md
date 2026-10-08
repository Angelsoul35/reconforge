# ADR 0001: One Collector Protocol and one Asset model

## Status

Accepted.

## Context

Recon data comes from many tools — subdomain enumeration, port scanning, HTTP
fingerprinting, TLS probing, passive sources like certificate transparency — each
with its own output format, and all overlapping on the same hosts. If the
aggregator knew about each tool's format directly, adding a source would mean
touching the core, and the merge/score logic would be tangled with parsing.

## Decision

Define a minimal `Collector` Protocol — `name` and
`collect(target) -> list[Asset]` — and a single normalised `Asset` model that
every collector maps its findings onto. Collectors return *partial* assets;
downstream code only ever sees `Asset`.

## Consequences

- **Adding a source is implementing the Protocol.** No change to normalisation,
  scoring, the service, or the API.
- **Sources compose.** A port scanner and a TLS probe each fill different fields
  of the same host, and normalisation merges them.
- **Testable.** Collectors are swapped for offline/fake ones with no special
  casing, because they are just another implementation of the Protocol.
- **Provenance.** Each asset records the `sources` that contributed, so a finding
  can be traced to the collector that produced it.
- **Trade-off.** The common model is a lowest common denominator — a collector
  with a very rich output must flatten it onto `Asset`'s fields. `Asset` is
  designed to be extended with new fields when a real need appears, keeping the
  Protocol stable.
