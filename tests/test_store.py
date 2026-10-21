from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import Engine

from backend.app.store import alert_count, insert_alert, latest_alerts, newest_alert_time
from tests.conftest import make_live_alert


def test_insert_is_idempotent(db: Engine) -> None:
    live, payload = make_live_alert("1.1", minute=0)
    assert insert_alert(db, live, payload) is True
    assert insert_alert(db, live, payload) is False
    assert alert_count(db) == 1


def test_latest_alerts_are_newest_first_and_round_trip(db: Engine) -> None:
    alerts = [make_live_alert(f"1.{n}", minute=n) for n in (1, 2, 3)]
    for live, payload in alerts:
        insert_alert(db, live, payload)
    latest = latest_alerts(db, limit=2)
    assert [a.wazuh_id for a in latest] == ["1.3", "1.2"]
    assert latest[0] == alerts[2][0]


def test_newest_alert_time(db: Engine) -> None:
    assert newest_alert_time(db) is None
    live, payload = make_live_alert("1.7", minute=7)
    insert_alert(db, live, payload)
    assert newest_alert_time(db) == datetime(2026, 9, 27, 9, 7, tzinfo=UTC)
