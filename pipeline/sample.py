from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.findings import assessment, finding_hosts
from backend.app.incidents import get_run, incident_summaries
from backend.app.store import alert_count, latest_alerts, newest_alert_time
from contracts.models import PcFeed, PcSample, PcStatus, ServiceState
from pipeline.sanitize import Sanitizer, forbidden_terms, leftovers

DEFAULT_OUT = Path("lab/wazuh/sample/pc-sample.json")
NOTE = (
    "Recorded sample from the author's own PC, with names and addresses replaced. "
    "Nothing here is live."
)
RECORDED = ServiceState(reachable=True, detail="Recorded sample.")


class SampleLeak(ValueError):
    pass


def build_sample(
    engine: Engine,
    now: datetime,
    *,
    alerts: int = 50,
    incidents: int = 30,
    findings: int = 25,
    runs: int = 10,
) -> PcSample:
    summaries = incident_summaries(engine, limit=incidents)
    status = PcStatus(
        checked_at=now,
        wazuh_api=RECORDED,
        backfill=RECORDED,
        alert_count=alert_count(engine),
        last_alert_at=newest_alert_time(engine),
        queue_length=0,
        model=RECORDED,
        sync=RECORDED,
    )
    feed = PcFeed(status=status, alerts=latest_alerts(engine, alerts), incidents=summaries)
    hosts = finding_hosts(engine)
    view = assessment(engine, hosts[0], now) if hosts else None
    if view is not None:
        kept = view.findings[:findings]
        ids = {finding.finding_id for finding in kept}
        view = view.model_copy(
            update={
                "findings": kept,
                "recommendations": [
                    r for r in view.recommendations if any(f in ids for f in r.finding_ids)
                ],
            }
        )
    investigated = [s for s in summaries if s.classification is not None][:runs]
    recorded = [get_run(engine, s.incident.incident_id) for s in investigated]
    return PcSample(
        created_at=now,
        note=NOTE,
        feed=feed,
        assessment=view,
        runs=[run for run in recorded if run is not None],
    )


def sanitize_sample(sample: PcSample, terms: list[str]) -> PcSample:
    data = sample.model_dump(mode="json")
    sanitizer = Sanitizer()
    sanitizer.learn(data)
    clean = sanitizer.apply(data)
    left = leftovers(clean, terms)
    if left:
        raise SampleLeak(f"These terms survived sanitizing: {', '.join(left)}")
    return PcSample.model_validate(clean)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.sample",
        description="Export a sanitized sample of the live My PC page for the public demo.",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    terms = forbidden_terms()
    if not terms:
        print("Set SENTINEL_FORBIDDEN_TERMS to your real user and computer names first.")
        return 2
    try:
        sample = sanitize_sample(build_sample(get_engine(), datetime.now(UTC)), terms)
    except SampleLeak as leak:
        print(f"{leak}. Nothing was written.")
        return 3
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(sample.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {args.out}. Review it before committing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
