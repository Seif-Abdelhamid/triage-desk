"""End-to-end against the docker compose stack. Skipped unless explicitly enabled.

Run with: docker compose up -d && TRIAGE_DESK_E2E=1 pytest -m integration
"""

from __future__ import annotations

import json
import os
import time
import uuid

import httpx
import pytest

from triage_desk.webhook_security import sign

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("TRIAGE_DESK_E2E") != "1",
        reason="needs `docker compose up` (set TRIAGE_DESK_E2E=1)",
    ),
]

API = os.environ.get("TRIAGE_DESK_API", "http://localhost:8000")


def test_signed_ping_and_replay_against_running_stack() -> None:
    secret = os.environ["GITHUB_WEBHOOK_SECRET"]
    body = json.dumps({"zen": "e2e"}).encode()
    delivery = str(uuid.uuid4())
    headers = {
        "X-GitHub-Event": "ping",
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": sign(secret, body),
    }
    assert httpx.post(f"{API}/webhook", content=body, headers=headers).json() == {"status": "pong"}
    again = httpx.post(f"{API}/webhook", content=body, headers=headers).json()
    assert again["status"] == "duplicate-delivery-ignored"
    time.sleep(0.1)
    assert "triage_desk_inflight_tasks" in httpx.get(f"{API}/metrics").text
