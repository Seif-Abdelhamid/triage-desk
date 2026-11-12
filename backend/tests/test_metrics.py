from __future__ import annotations

import fakeredis
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from triage_desk import metrics
from triage_desk.config import Settings
from triage_desk.main import create_app

from .fakes import FakeQueue


def r() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True)


def test_depth_and_inflight_are_separate_signals() -> None:
    client = r()
    for i in range(3):
        client.rpush("scans", f"task{i}")
    metrics.mark_started(client, "t-a")
    metrics.mark_started(client, "t-b")
    stats = metrics.collect(client, "scans", stale_after_s=900, target_per_worker=2)
    assert (stats.depth, stats.inflight) == (3, 2)
    assert stats.desired_workers == 3  # ceil(5 / 2)


def test_empty_queue_but_busy_workers_still_wants_workers() -> None:
    # The case that motivates the ADR: depth 0, workers mid-scan.
    client = r()
    for t in ("a", "b", "c", "d"):
        metrics.mark_started(client, t)
    stats = metrics.collect(client, "scans", stale_after_s=900, target_per_worker=2)
    assert stats.depth == 0
    assert stats.desired_workers == 2


def test_finished_tasks_leave_inflight() -> None:
    client = r()
    metrics.mark_started(client, "x")
    metrics.mark_finished(client, "x")
    assert metrics.inflight_count(client, stale_after_s=900) == 0


def test_stale_entries_from_dead_workers_are_pruned() -> None:
    client = r()
    metrics.mark_started(client, "dead", now=0)
    metrics.mark_started(client, "alive", now=1000)
    assert metrics.inflight_count(client, stale_after_s=900, now=1001) == 1


def test_prometheus_endpoint(settings: Settings, sessions: sessionmaker[Session]) -> None:
    client = r()
    client.rpush("scans", "x")
    metrics.mark_started(client, "y")
    app = create_app(settings, sessions, FakeQueue(), redis_client=client)
    body = TestClient(app).get("/metrics").text
    assert 'triage_desk_queue_depth{queue="scans"} 1' in body
    assert 'triage_desk_inflight_tasks{queue="scans"} 1' in body
    assert 'triage_desk_desired_workers{queue="scans"} 1' in body
    assert "# TYPE triage_desk_inflight_tasks gauge" in body


def test_celery_signals_track_inflight(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from triage_desk import worker

    client = r()
    monkeypatch.setattr(worker, "_redis", client)
    worker._on_start(task_id="abc")
    assert metrics.inflight_count(client, 900) == 1
    worker._on_finish(task_id="abc")
    assert metrics.inflight_count(client, 900) == 0
    assert worker.app.conf.worker_prefetch_multiplier == 1
    assert worker.app.conf.task_acks_late is True
