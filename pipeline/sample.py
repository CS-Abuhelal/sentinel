from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.findings import FIX_TOP, advice_unit, assessment, finding_hosts
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
MAX_SCANNED_INCIDENTS = 10000
UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
WORD_BREAKS = re.compile(r"[\s._+]+")
MAX_DECODES = 3


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
    every = incident_summaries(engine, limit=MAX_SCANNED_INCIDENTS)
    investigated = [s for s in every if s.classification is not None][: min(runs, incidents)]
    chosen = {s.incident.incident_id for s in investigated}
    others = [s for s in every if s.incident.incident_id not in chosen]
    chosen |= {s.incident.incident_id for s in others[: incidents - len(investigated)]}
    summaries = [s for s in every if s.incident.incident_id in chosen]
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
        leads: dict[str, str] = {}
        for finding in view.findings:
            leads.setdefault(advice_unit(finding), finding.finding_id)
        fixed = set(list(leads.values())[:FIX_TOP])
        ids = {finding.finding_id for finding in view.findings[:findings]} | fixed
        kept = [finding for finding in view.findings if finding.finding_id in ids]
        view = view.model_copy(
            update={
                "findings": kept,
                "recommendations": [
                    r for r in view.recommendations if any(f in ids for f in r.finding_ids)
                ],
            }
        )
    recorded = [get_run(engine, s.incident.incident_id) for s in investigated]
    return PcSample(
        created_at=now,
        note=NOTE,
        feed=feed,
        assessment=view,
        runs=[run for run in recorded if run is not None],
    )


def _texts(doc: Any) -> Iterator[str]:
    if isinstance(doc, dict):
        for key, value in doc.items():
            yield str(key)
            yield from _texts(value)
    elif isinstance(doc, list):
        for value in doc:
            yield from _texts(value)
    elif doc is not None:
        yield str(doc)


def _decoded(text: str) -> str:
    for _ in range(MAX_DECODES):
        step = unquote(UNICODE_ESCAPE.sub(lambda found: chr(int(found.group(1), 16)), text))
        if step == text:
            break
        text = step
    return text


def _spaced(text: str) -> str:
    return WORD_BREAKS.sub(" ", text).strip()


def _surviving(clean: Any, terms: list[str]) -> list[str]:
    texts = list(_texts(clean))
    decoded = [_decoded(text) for text in texts]
    spaced = [_spaced(text) for text in decoded]
    found = set(leftovers(texts + decoded, terms))
    found.update(term for term in terms if leftovers(spaced, [_spaced(term)]))
    return [term for term in terms if term in found]


def sanitize_sample(sample: PcSample, terms: list[str]) -> PcSample:
    data = sample.model_dump(mode="json")
    sanitizer = Sanitizer()
    sanitizer.learn(data)
    clean = sanitizer.apply(data)
    left = _surviving(clean, terms)
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
