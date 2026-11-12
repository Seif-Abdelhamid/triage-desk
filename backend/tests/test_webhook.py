from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from triage_desk.config import Settings
from triage_desk.main import create_app
from triage_desk.models import WebhookDelivery, utcnow
from triage_desk.webhook_security import prune_deliveries, sign, verify_signature

from .fakes import FakeQueue

SECRET = "test-secret"


def pr_payload(action: str = "opened", draft: bool = False) -> dict[str, object]:
    return {
        "action": action,
        "repository": {"full_name": "acme/app"},
        "pull_request": {"number": 7, "draft": draft, "head": {"sha": "a" * 40}},
    }


@pytest.fixture
def queue() -> FakeQueue:
    return FakeQueue()


@pytest.fixture
def client(settings: Settings, sessions: sessionmaker[Session], queue: FakeQueue) -> TestClient:
    return TestClient(create_app(settings, sessions, queue))


def post(
    client: TestClient,
    payload: object,
    event: str = "pull_request",
    delivery: str = "d-1",
    secret: str = SECRET,
    signature: str | None = None,
):
    body = json.dumps(payload).encode()
    headers = {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": signature if signature is not None else sign(secret, body),
        "Content-Type": "application/json",
    }
    return client.post("/webhook", content=body, headers=headers)


# ------------------------------------------------------------- signature unit tests


def test_verify_signature_accepts_valid() -> None:
    body = b'{"a":1}'
    assert verify_signature(SECRET, body, sign(SECRET, body))


@pytest.mark.parametrize(
    "header",
    [None, "", "sha1=" + "0" * 40, "sha256=" + "0" * 64, "sha256=zz", "sha256=" + "A" * 64],
)
def test_verify_signature_rejects_bad_headers(header: str | None) -> None:
    assert not verify_signature(SECRET, b"{}", header)


def test_verify_signature_rejects_tampered_body() -> None:
    sig = sign(SECRET, b'{"action":"opened"}')
    assert not verify_signature(SECRET, b'{"action":"closed"}', sig)


def test_verify_signature_fails_closed_without_secret() -> None:
    assert not verify_signature("", b"{}", sign("", b"{}"))


def test_verify_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    import triage_desk.webhook_security as ws

    calls: list[tuple[str, str]] = []
    real = ws.hmac.compare_digest

    def spy(a: str, b: str) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(ws.hmac, "compare_digest", spy)
    body = b"{}"
    assert ws.verify_signature(SECRET, body, sign(SECRET, body))
    assert len(calls) == 1


# ------------------------------------------------------------- endpoint tests


def test_pull_request_enqueues_scan(client: TestClient, queue: FakeQueue) -> None:
    r = post(client, pr_payload())
    assert r.status_code == 200
    assert r.json()["status"] == "scan-enqueued"
    assert queue.scans == [("acme/app", 7, "a" * 40)]


def test_bad_signature_is_401_and_nothing_enqueued(client: TestClient, queue: FakeQueue) -> None:
    r = post(client, pr_payload(), signature="sha256=" + "0" * 64)
    assert r.status_code == 401
    assert queue.scans == []


def test_wrong_secret_is_401(client: TestClient) -> None:
    assert post(client, pr_payload(), secret="attacker-guess").status_code == 401


def test_replayed_delivery_is_ignored(client: TestClient, queue: FakeQueue) -> None:
    assert post(client, pr_payload(), delivery="same-id").json()["status"] == "scan-enqueued"
    r = post(client, pr_payload(), delivery="same-id")
    assert r.status_code == 200
    assert r.json()["status"] == "duplicate-delivery-ignored"
    assert len(queue.scans) == 1


def test_missing_delivery_id_rejected(client: TestClient) -> None:
    assert post(client, pr_payload(), delivery="").status_code == 400
    assert post(client, pr_payload(), delivery="../../etc").status_code == 400


def test_secret_not_configured_fails_closed(sessions: sessionmaker[Session]) -> None:
    c = TestClient(create_app(Settings(webhook_secret=""), sessions, FakeQueue()))
    assert post(c, pr_payload(), secret="").status_code == 503


def test_oversized_payload_rejected(sessions: sessionmaker[Session]) -> None:
    c = TestClient(
        create_app(Settings(webhook_secret=SECRET, max_webhook_bytes=100), sessions, FakeQueue())
    )
    assert post(c, {"pad": "x" * 500}).status_code == 413


def test_draft_and_closed_prs_not_scanned(client: TestClient, queue: FakeQueue) -> None:
    assert post(client, pr_payload(draft=True), delivery="d1").json()["status"] == "ignored-draft"
    assert post(client, pr_payload("closed"), delivery="d2").json()["status"] == "ignored"
    assert queue.scans == []


def test_ping(client: TestClient) -> None:
    assert post(client, {"zen": "hi"}, event="ping").json()["status"] == "pong"


def test_issue_comment_with_command_enqueues(client: TestClient, queue: FakeQueue) -> None:
    payload = {
        "action": "created",
        "repository": {"full_name": "acme/app"},
        "issue": {"number": 7, "pull_request": {}},
        "comment": {
            "id": 55,
            "body": "/triage fixed #3",
            "user": {"login": "alice", "type": "User"},
        },
    }
    assert post(client, payload, event="issue_comment").json()["status"] == "triage-enqueued"
    ev = queue.comments[0]
    assert (ev.repo, ev.pr, ev.author, ev.is_review_comment) == ("acme/app", 7, "alice", False)


def test_review_reply_carries_thread_id(client: TestClient, queue: FakeQueue) -> None:
    payload = {
        "action": "created",
        "repository": {"full_name": "acme/app"},
        "pull_request": {"number": 7},
        "comment": {
            "id": 56,
            "in_reply_to_id": 1001,
            "body": "/triage false-positive test code",
            "user": {"login": "alice", "type": "User"},
        },
    }
    post(client, payload, event="pull_request_review_comment")
    assert queue.comments[0].in_reply_to_id == 1001
    assert queue.comments[0].is_review_comment


def test_non_command_and_plain_issue_comments_ignored(client: TestClient, queue: FakeQueue) -> None:
    base = {
        "action": "created",
        "repository": {"full_name": "acme/app"},
        "comment": {"id": 1, "body": "looks good", "user": {"login": "a", "type": "User"}},
    }
    assert (
        post(
            client,
            {**base, "issue": {"number": 1, "pull_request": {}}},
            event="issue_comment",
            delivery="x1",
        ).json()["status"]
        == "ignored"
    )
    plain_issue = {
        **base,
        "issue": {"number": 1},
        "comment": {**base["comment"], "body": "/triage fixed"},
    }  # type: ignore[dict-item]
    assert (
        post(client, plain_issue, event="issue_comment", delivery="x2").json()["status"]
        == "ignored"
    )
    assert queue.comments == []


def test_prune_deliveries(session: Session) -> None:
    session.add(
        WebhookDelivery(delivery_id="old", event="ping", received_at=utcnow() - timedelta(days=10))
    )
    session.add(WebhookDelivery(delivery_id="new", event="ping"))
    session.flush()
    assert prune_deliveries(session, window_s=7 * 24 * 3600) == 1
    assert [d.delivery_id for d in session.scalars(select(WebhookDelivery))] == ["new"]


def test_metrics_requires_redis(client: TestClient) -> None:
    assert client.get("/metrics").status_code == 503


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
