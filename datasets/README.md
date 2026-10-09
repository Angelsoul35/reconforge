# Datasets

## `cvss_cwe_snapshot.jsonl` — real NVD/CVE records with CVSS v3.1 base metrics

A frozen snapshot used to validate reconforge's scoring engine against the
industry-standard severity scale (see `reconforge/real_benchmark.py` and
`docs/estudio/04-validacion-con-datos-reales.md`).

### Source and provenance

| | |
| --- | --- |
| Hugging Face dataset | [`bziemba/cve_cwe_cvss`](https://huggingface.co/datasets/bziemba/cve_cwe_cvss) |
| Upstream records | U.S. **NVD** / the **CVE Program** (MITRE) — public vulnerability records |
| Scoring standard | **CVSS v3.1**, a free, open standard published by **FIRST.org** |
| Access path | `datasets-server.huggingface.co` rows API (no auth, rate-limited) |

The Hugging Face card declares no explicit license. The underlying data is
public: NVD records are a work of the U.S. government and carry no copyright, CVE
records are distributed by the CVE Program for public use, and CVSS is an open
standard anyone may implement. This snapshot redistributes a subset of those
public records for reproducible validation and cites its upstreams here.

### What is vendored

- **12,000 rows**, JSON Lines (one object per line).
- Columns kept (the CVSS v3.1 base-metric vector plus identity):

  | snapshot field | meaning | values |
  | --- | --- | --- |
  | `cve_id` | CVE identifier | e.g. `CVE-2025-50475` |
  | `date` | NVD publication date | ISO date |
  | `cwe_base_id`, `cwe_base_name` | associated weakness (CWE) | e.g. `CWE-79` |
  | `cvss_av` | Attack Vector | Network / Adjacent Network / Local / Physical |
  | `cvss_ac` | Attack Complexity | Low / High |
  | `cvss_pr` | Privileges Required | None / Low / High |
  | `cvss_ui` | User Interaction | None / Required |
  | `cvss_s` | Scope | Unchanged / Changed |
  | `cvss_c` / `cvss_i` / `cvss_a` | Confidentiality / Integrity / Availability impact | High / Low / None |

### Mapping into reconforge

`reconforge/real_data.py` parses each row into a `CvssRecord` and derives the
**gold label** — the official CVSS v3.1 severity — with the exact FIRST.org
base-score formula (`cvss_base_score` / `gold_severity`):

```
ISS        = 1 - (1-C)(1-I)(1-A)
Impact     = 6.42 * ISS                               (Scope unchanged)
           = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15    (Scope changed)
Exploit.   = 8.22 * AV * AC * PR * UI
BaseScore  = Roundup(min(Impact + Exploit., 10))      (x1.08 if Scope changed)
Severity   = None 0.0 | Low 0.1-3.9 | Medium 4.0-6.9 | High 7.0-8.9 | Critical 9.0-10.0
```

CVSS "None" maps to reconforge's `INFO` level. `reconforge/severity_model.py`
then turns the eight metrics into reconforge `ExposureFinding`s and scores them
through the same `aggregate` engine the port/TLS/tech rules use, with weights
calibrated to this corpus.

### Regeneration

```bash
python -m reconforge.real_data
```

This re-fetches from the rows API and rewrites `cvss_cwe_snapshot.jsonl`. The
sample is **deterministic**: it pulls evenly spread 100-row blocks across the full
dataset (`offset = i * (total // n_blocks)`), so the snapshot is representative of
the whole corpus and reproducible regardless of source row order. Fetching is
paced and retried with exponential, `Retry-After`-aware backoff to respect the
API's rate limit.

### Gold severity distribution (this snapshot)

| severity | count | share |
| --- | --- | --- |
| info (CVSS None) | 58 | 0.005 |
| low | 659 | 0.055 |
| medium | 5680 | 0.473 |
| high | 4321 | 0.360 |
| critical | 1282 | 0.107 |
