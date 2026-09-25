from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import TypeAdapter

from contracts.models import IncidentRun

_RUNS = TypeAdapter(list[IncidentRun])


def export_runs(runs_dir: Path, out: Path) -> list[IncidentRun]:
    runs = [
        IncidentRun.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(runs_dir.glob("*.json"))
    ]
    if not runs:
        raise ValueError(f"no run files in {runs_dir}")
    runs.sort(key=lambda r: r.created_at, reverse=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(_RUNS.dump_json(runs))
    return runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.export",
        description="Bundle run files into one JSON array for the static dashboard.",
    )
    parser.add_argument("runs_dir", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args(argv)
    runs = export_runs(args.runs_dir, args.out)
    print(f"wrote {len(runs)} run{'' if len(runs) == 1 else 's'} to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
