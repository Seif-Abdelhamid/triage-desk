"""Celery app and tasks. Start with: celery -A triage_desk.worker worker -Q scans"""

from __future__ import annotations

from typing import Any

import redis
from celery import Celery
from celery.signals import task_postrun, task_prerun

from . import metrics
from .config import get_settings
from .db import session_scope
from .github_client import HttpGitHubClient
from .jobs import CommentEvent, handle_comment, run_scan
from .scanner import SemgrepCli

settings = get_settings()
app = Celery("triage_desk", broker=settings.redis_url)
app.conf.update(
    task_default_queue=settings.scan_queue,
    task_acks_late=True,  # a crashed worker's task is redelivered...
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # ...and workers do not hoard queued tasks
    task_time_limit=settings.task_hard_limit_s,
    task_soft_time_limit=max(30, settings.task_hard_limit_s - 30),
    task_serializer="json",
    accept_content=["json"],
)

_redis: redis.Redis | None = None


def _r() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis


@task_prerun.connect
def _on_start(task_id: str | None = None, **_: Any) -> None:
    if task_id:
        metrics.mark_started(_r(), task_id)


@task_postrun.connect
def _on_finish(task_id: str | None = None, **_: Any) -> None:
    if task_id:
        metrics.mark_finished(_r(), task_id)


def _gh() -> HttpGitHubClient:
    return HttpGitHubClient(settings.github_token, settings.github_api_url)


@app.task(
    name="triage_desk.scan_pull_request",
    autoretry_for=(ConnectionError,),
    retry_backoff=True,
    max_retries=3,
)
def scan_pull_request(repo: str, pr: int, head_sha: str) -> dict[str, Any]:
    scanner = SemgrepCli(settings.semgrep_config, settings.semgrep_timeout_s)
    with session_scope() as session:
        summary = run_scan(session, _gh(), scanner, settings, repo, pr, head_sha)
    return summary.__dict__


@app.task(name="triage_desk.triage_comment")
def triage_comment(event: dict[str, Any]) -> str:
    with session_scope() as session:
        return handle_comment(session, _gh(), settings, CommentEvent(**event))
