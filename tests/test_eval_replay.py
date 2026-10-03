from __future__ import annotations

from pathlib import Path

import pytest

from eval import run as eval_run
from pipeline.run import REPO

RESULTS = REPO / "eval" / "results.json"
REPORT = REPO / "docs" / "eval-results.md"


@pytest.mark.skip(reason="re-recording after the case_id fix")
@pytest.mark.skipif(not RESULTS.is_file(), reason="the evaluation has not been recorded")
def test_replaying_the_recordings_reproduces_the_committed_results(tmp_path: Path) -> None:
    results = tmp_path / "results.json"
    report = tmp_path / "eval-results.md"
    assert eval_run.main(["--results", str(results), "--report", str(report)]) == 0
    assert results.read_bytes() == RESULTS.read_bytes()
    assert report.read_bytes() == REPORT.read_bytes()
