"""FastAPI app: GitHub webhook receiver, dashboard JSON API, /metrics."""

import json
import logging
from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import metrics, stats
from .config import Settings, get_settings
from .jobs import CommentEvent
from .models import Finding, FindingStatus
from .queue import JobQueue
from .webhook_security import record_delivery, valid_delivery_id, verify_signature

log = logging.getLogger(__name__)
SCAN_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}


def _comment_event(event: str, payload: dict[str, Any]) -> CommentEvent | None:
    if payload.get("action") != "created":
        return None
    comment = payload.get("comment") or {}
    user = comment.get("user") or {}
    repo = (payload.get("repository") or {}).get("full_name")
    body = comment.get("body") or ""
    if not repo or not body.lstrip().startswith("/triage"):
        return None
    if event == "issue_comment":
        issue = payload.get("issue") or {}
        if "pull_request" not in issue:  # plain issue, not a PR
            return None
        pr = issue.get("number")
        reply_to = None
        is_review = False
    else:  # pull_request_review_comment
        pr = (payload.get("pull_request") or {}).get("number")
        reply_to = comment.get("in_reply_to_id")
        is_review = True
    if not isinstance(pr, int):
        return None
    return CommentEvent(
        repo=repo,
        pr=pr,
        comment_id=int(comment["id"]),
        author=str(user.get("login", "")),
        author_type=str(user.get("type", "")),
        body=body[:5000],
        in_reply_to_id=int(reply_to) if reply_to else None,
        is_review_comment=is_review,
    )


def create_app(
    settings: Settings, sessions: sessionmaker[Session], queue: JobQueue, redis_client: Any = None
) -> FastAPI:
    app = FastAPI(title="triage-desk", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET"],
        allow_headers=[],
    )

    def db() -> Iterator[Session]:
        s = sessions()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/webhook")
    async def webhook(request: Request) -> dict[str, str]:
        if not settings.webhook_secret:
            raise HTTPException(503, "webhook secret not configured")
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_webhook_bytes:
            raise HTTPException(413, "payload too large")
        body = await request.body()  # raw bytes: verify before parsing anything
        if len(body) > settings.max_webhook_bytes:
            raise HTTPException(413, "payload too large")
        if not verify_signature(
            settings.webhook_secret, body, request.headers.get("x-hub-signature-256")
        ):
            raise HTTPException(401, "invalid signature")
        delivery = request.headers.get("x-github-delivery")
        event = request.headers.get("x-github-event", "")
        if delivery is None or not valid_delivery_id(delivery):
            raise HTTPException(400, "missing or invalid X-GitHub-Delivery")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, "invalid JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(400, "invalid payload")

        with sessions.begin() as s:
            if not record_delivery(s, delivery, event[:64]):
                return {"status": "duplicate-delivery-ignored"}

        if event == "ping":
            return {"status": "pong"}
        if event == "pull_request" and payload.get("action") in SCAN_ACTIONS:
            pr = payload.get("pull_request") or {}
            repo = (payload.get("repository") or {}).get("full_name")
            sha = (pr.get("head") or {}).get("sha")
            if pr.get("draft"):
                return {"status": "ignored-draft"}
            if not (repo and isinstance(pr.get("number"), int) and isinstance(sha, str)):
                raise HTTPException(400, "incomplete pull_request payload")
            queue.enqueue_scan(repo, pr["number"], sha)
            return {"status": "scan-enqueued"}
        if event in ("issue_comment", "pull_request_review_comment"):
            ev = _comment_event(event, payload)
            if ev is None:
                return {"status": "ignored"}
            queue.enqueue_comment(ev)
            return {"status": "triage-enqueued"}
        return {"status": "ignored"}

    @app.get("/api/stats")
    def api_stats(session: Annotated[Session, Depends(db)]) -> dict[str, object]:
        return stats.compute(session)

    @app.get("/api/findings")
    def api_findings(
        session: Annotated[Session, Depends(db)],
        status: FindingStatus | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> list[dict[str, object]]:
        q = select(Finding).order_by(Finding.id.desc()).limit(limit)
        if status is not None:
            q = q.where(Finding.status == status)
        return [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "path": f.path,
                "line": f.line,
                "severity": f.severity,
                "status": f.status.value,
                "pr_number": f.pr_number,
                "reachability": f.reachability.value,
                "created_at": f.created_at.isoformat(),
            }
            for f in session.scalars(q)
        ]

    @app.get("/metrics")
    def metrics_endpoint() -> Response:
        if redis_client is None:
            raise HTTPException(503, "redis not configured")
        snapshot = metrics.collect(
            redis_client,
            settings.scan_queue,
            settings.task_hard_limit_s,
            settings.target_tasks_per_worker,
        )
        return Response(metrics.prometheus_text(snapshot), media_type="text/plain; version=0.0.4")

    return app


def build_default_app() -> FastAPI:  # pragma: no cover - wiring for uvicorn
    import redis

    from .db import session_factory
    from .queue import CeleryJobQueue

    settings = get_settings()
    return create_app(
        settings,
        session_factory(),
        CeleryJobQueue(),
        redis.Redis.from_url(settings.redis_url, decode_responses=True),
    )
