"""Real-world validation data: NVD/CVE records with their CVSS v3.1 base metrics.

reconforge scores security findings into a severity level with a transparent,
weighted rule engine. The canonical severity standard for security findings is
CVSS, so the natural real-data question is whether reconforge's engine — the same
``findings -> score -> level`` machinery that scores port/TLS/tech exposures — can
reproduce the authoritative CVSS severity on a large corpus of real vulnerabilities.

This module provides that corpus and the ground truth:

* :func:`load_cvss_dataset` reads the vendored snapshot under ``datasets/``.
* :func:`fetch_cvss_rows` regenerates the snapshot from the Hugging Face
  ``datasets-server`` rows API (retries, a monkeypatchable ``urlopen`` seam).
* :func:`cvss_base_score` / :func:`gold_severity` compute the **gold label** with
  the official CVSS v3.1 base-score formula (FIRST.org) — not an invented label.

Source dataset: ``bziemba/cve_cwe_cvss`` on Hugging Face, a tabular compilation of
public NVD records (CVE Program / MITRE) with the CVSS v3 base-metric vector split
into its eight components. See ``datasets/README.md`` for provenance and licensing.
"""

from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .models import Severity

# --- source / layout ---------------------------------------------------------

DATASET_ID = "bziemba/cve_cwe_cvss"
HF_ROWS_URL = "https://datasets-server.huggingface.co/rows"
SNAPSHOT_PATH = Path(__file__).resolve().parent.parent / "datasets" / "cvss_cwe_snapshot.jsonl"

# The columns we keep from each source row (the CVSS base-metric vector + identity).
SNAPSHOT_FIELDS = (
    "cve_id",
    "date",
    "cwe_base_id",
    "cwe_base_name",
    "cvss_av",
    "cvss_ac",
    "cvss_pr",
    "cvss_ui",
    "cvss_s",
    "cvss_c",
    "cvss_i",
    "cvss_a",
)

# A seam so tests can inject a fake network layer. Override via this name
# (``monkeypatch.setattr(real_data, "urlopen", fake)``) or the ``opener`` argument.
urlopen = urllib.request.urlopen


# --- the record and its parsed metric vector ---------------------------------


@dataclass(frozen=True)
class CvssRecord:
    """One real vulnerability: identity plus the eight CVSS v3.1 base metrics.

    Metric values use the dataset's spellings: ``cvss_av`` in
    {Network, Adjacent Network, Local, Physical}, ``cvss_ac`` in {Low, High},
    ``cvss_pr`` in {None, Low, High}, ``cvss_ui`` in {None, Required},
    ``cvss_s`` in {Unchanged, Changed}, and ``cvss_c/i/a`` in {High, Low, None}.
    """

    cve_id: str
    av: str
    ac: str
    pr: str
    ui: str
    scope: str
    conf: str
    integ: str
    avail: str
    cwe: str | None = None
    date: str | None = None

    @classmethod
    def from_row(cls, row: dict) -> CvssRecord:
        return cls(
            cve_id=str(row.get("cve_id")),
            av=str(row.get("cvss_av")),
            ac=str(row.get("cvss_ac")),
            pr=str(row.get("cvss_pr")),
            ui=str(row.get("cvss_ui")),
            scope=str(row.get("cvss_s")),
            conf=str(row.get("cvss_c")),
            integ=str(row.get("cvss_i")),
            avail=str(row.get("cvss_a")),
            cwe=(row.get("cwe_base_name") or None),
            date=(row.get("date") or None),
        )

    def metrics(self) -> dict[str, str]:
        """The eight base metrics as an ordered name -> value mapping."""
        return {
            "AV": self.av,
            "AC": self.ac,
            "PR": self.pr,
            "UI": self.ui,
            "S": self.scope,
            "C": self.conf,
            "I": self.integ,
            "A": self.avail,
        }


# --- the gold label: official CVSS v3.1 base score (FIRST.org) ----------------

_AV = {"Network": 0.85, "Adjacent Network": 0.62, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2}
_AC = {"Low": 0.77, "High": 0.44}
_UI = {"None": 0.85, "Required": 0.62}
_CIA = {"High": 0.56, "Low": 0.22, "None": 0.0}


def _privileges_required(value: str, scope_changed: bool) -> float | None:
    if value == "None":
        return 0.85
    if value == "Low":
        return 0.68 if scope_changed else 0.62
    if value == "High":
        return 0.50 if scope_changed else 0.27
    return None


def _roundup(value: float) -> float:
    """CVSS v3.1 ``Roundup``: smallest one-decimal number >= value."""
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def cvss_base_score(rec: CvssRecord) -> float | None:
    """The official CVSS v3.1 base score (0.0-10.0), or ``None`` if unparseable."""
    try:
        av = _AV[rec.av]
        ac = _AC[rec.ac]
        ui = _UI[rec.ui]
        conf = _CIA[rec.conf]
        integ = _CIA[rec.integ]
        avail = _CIA[rec.avail]
    except KeyError:
        return None
    scope_changed = rec.scope.lower().startswith("c")
    pr = _privileges_required(rec.pr, scope_changed)
    if pr is None:
        return None

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


# CVSS v3.1 severity bands, expressed on reconforge's own Severity vocabulary.
# CVSS "None" (score 0.0) maps to reconforge's INFO (an asset with nothing to flag).
CVSS_BANDS: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]


def severity_for_score(score: float) -> Severity:
    """Map a CVSS 0-10 score to a reconforge Severity using the official bands."""
    for threshold, level in CVSS_BANDS:
        if score >= threshold:
            return level
    return Severity.INFO


def gold_severity(rec: CvssRecord) -> Severity | None:
    """Ground-truth severity: the official CVSS v3.1 severity of ``rec``."""
    score = cvss_base_score(rec)
    if score is None:
        return None
    return severity_for_score(score)


# --- loading the vendored snapshot -------------------------------------------


def load_cvss_dataset(path: Path | str = SNAPSHOT_PATH) -> list[CvssRecord]:
    """Load the vendored snapshot, skipping rows whose gold label is unparseable."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"snapshot not found at {path}; regenerate it with "
            "`python -m reconforge.real_data` (see datasets/README.md)"
        )
    records: list[CvssRecord] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rec = CvssRecord.from_row(json.loads(line))
            if gold_severity(rec) is not None:
                records.append(rec)
    return records


# --- regenerating the snapshot from the live API -----------------------------


def _get_json(
    url: str,
    *,
    opener: Callable,
    retries: int,
    backoff: float,
    sleep: Callable[[float], None],
    timeout: float,
) -> dict:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            with opener(url, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # network / decode errors are retried
            last = exc
            if attempt == retries - 1:
                break
            wait = backoff * (2**attempt)
            # Rate-limit (429) replies need a longer, header-aware pause.
            if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    wait = max(wait, float(retry_after)) if retry_after else max(wait, 15.0)
                except (TypeError, ValueError):
                    wait = max(wait, 15.0)
            sleep(wait)
    raise RuntimeError(f"failed to fetch {url} after {retries} attempts: {last}") from last


def fetch_cvss_rows(
    n_rows: int = 12_000,
    *,
    dataset: str = DATASET_ID,
    block: int = 100,
    opener: Callable | None = None,
    retries: int = 6,
    backoff: float = 4.0,
    pause: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
    timeout: float = 60.0,
    progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    """Fetch a deterministic, representative sample from the HF rows API.

    The sample is spread evenly across the full dataset (every ``step``-th block),
    so it is reproducible and not biased by the source row order. Each HTTP call is
    retried with exponential backoff, and ``pause`` throttles between blocks to stay
    under the API's rate limit. ``opener`` (defaulting to the module-level
    :data:`urlopen`) is the network seam the tests replace.
    """
    _open = opener if opener is not None else urlopen
    enc = urllib.parse.quote(dataset, safe="")

    def pull(offset: int, length: int) -> dict:
        url = (
            f"{HF_ROWS_URL}?dataset={enc}&config=default&split=train"
            f"&offset={offset}&length={length}"
        )
        return _get_json(
            url, opener=_open, retries=retries, backoff=backoff, sleep=sleep, timeout=timeout
        )

    total = int(pull(0, 1)["num_rows_total"])
    n_blocks = max(1, min(n_rows // block, total // block if total >= block else 1))
    step = max(1, total // n_blocks)

    rows: list[dict] = []
    for i in range(n_blocks):
        offset = min(i * step, max(0, total - block))
        for item in pull(offset, block).get("rows", []):
            source = item["row"]
            rows.append({field: source.get(field) for field in SNAPSHOT_FIELDS})
        if progress is not None:
            progress(i + 1, n_blocks)
        if len(rows) >= n_rows:
            break
        if pause:
            sleep(pause)
    return rows[:n_rows]


def write_snapshot(rows: list[dict], path: Path | str = SNAPSHOT_PATH) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def _iter_distribution(records: list[CvssRecord]) -> Iterator[tuple[Severity, int]]:
    counts: dict[Severity, int] = {}
    for rec in records:
        level = gold_severity(rec)
        if level is not None:
            counts[level] = counts.get(level, 0) + 1
    yield from sorted(counts.items(), key=lambda kv: kv[0].value)


if __name__ == "__main__":  # regenerate the vendored snapshot
    import sys

    print(f"Fetching CVSS/CWE rows from {DATASET_ID} ...")

    def _progress(done: int, total_blocks: int) -> None:
        if done % 10 == 0 or done == total_blocks:
            print(f"  {done}/{total_blocks} blocks", file=sys.stderr, flush=True)

    fetched = fetch_cvss_rows(progress=_progress)
    out = write_snapshot(fetched)
    print(f"Wrote {len(fetched)} rows to {out}")
    loaded = load_cvss_dataset(out)
    print(f"Parsed {len(loaded)} rows with a valid CVSS v3.1 gold label:")
    for level, count in _iter_distribution(loaded):
        print(f"  {level.value:9s} {count:6d}  {count / len(loaded):.3f}")
