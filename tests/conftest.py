from __future__ import annotations

import pytest

from reconforge.real_benchmark import run_benchmark
from reconforge.real_data import load_cvss_dataset


@pytest.fixture(scope="session")
def cvss_records():
    return load_cvss_dataset()


@pytest.fixture(scope="session")
def benchmark_result(cvss_records):
    # Run the full real-data benchmark once and share it across the suite.
    return run_benchmark(cvss_records, k=5, seed=0)
