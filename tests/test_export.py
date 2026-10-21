from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import TypeAdapter

from contracts.models import Classification, IncidentRun
from pipeline import export, run
from tests.conftest import S1_LOG


def test_export_bundles_run_files(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    out = tmp_path / "site" / "runs.json"
    assert run.main([str(S1_LOG), "--out", str(runs_dir)]) == 0
    assert export.main([str(runs_dir), str(out)]) == 0
    runs = TypeAdapter(list[IncidentRun]).validate_json(out.read_bytes())
    assert [r.case_id for r in runs] == ["s1_attack"]
    assert runs[0].verdict.classification is Classification.MALICIOUS


def test_export_without_runs_fails(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no run files"):
        export.export_runs(tmp_path, tmp_path / "runs.json")
