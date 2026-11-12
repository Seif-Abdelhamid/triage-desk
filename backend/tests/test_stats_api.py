from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from triage_desk.config import Settings
from triage_desk.main import create_app
from triage_desk.models import Finding, FindingStatus, Repository, Scan, utcnow
from triage_desk.stats import compute

from .fakes import FakeQueue


def seed(session: Session) -> None:
    repo = Repository(full_name="acme/app")
    session.add(repo)
    session.flush()
    scan = Scan(repo_id=repo.id, pr_number=1, head_sha="a" * 40)
    session.add(scan)
    session.flush()
    t0 = utcnow() - timedelta(days=1)
    rows = [
        ("rule.a", FindingStatus.false_positive, 60),
        ("rule.a", FindingStatus.false_positive, 180),
        ("rule.a", FindingStatus.fixed, 600),
        ("rule.a", FindingStatus.open, None),
        ("rule.b", FindingStatus.accepted_risk, 3600),
        ("rule.c", FindingStatus.open, None),
    ]
    for i, (rule, status, secs) in enumerate(rows):
        session.add(
            Finding(
                repo_id=repo.id,
                fingerprint=f"fp{i}",
                rule_id=rule,
                path="a.py",
                line=i + 1,
                severity="ERROR",
                message="m",
                pr_number=1,
                first_scan_id=scan.id,
                last_scan_id=scan.id,
                status=status,
                created_at=t0,
                first_triaged_at=t0 + timedelta(seconds=secs) if secs is not None else None,
            )
        )
    session.commit()


def test_compute_per_rule(session: Session) -> None:
    seed(session)
    data = compute(session)
    rules = {r["rule_id"]: r for r in data["rules"]}  # type: ignore[attr-defined, index]
    a = rules["rule.a"]
    assert (a["findings"], a["open"], a["triaged"], a["false_positives"]) == (4, 1, 3, 2)
    assert a["fp_rate"] == round(2 / 3, 4)  # denominator: triaged, not total
    assert a["median_time_to_triage_s"] == 180
    assert rules["rule.b"]["fp_rate"] == 0.0
    assert rules["rule.c"]["fp_rate"] is None  # nothing triaged yet -> unknown, not 0
    assert rules["rule.c"]["median_time_to_triage_s"] is None
    totals = data["totals"]
    assert totals == {
        "findings": 6,
        "triaged": 4,
        "false_positives": 2,
        "fp_rate": 0.5,
        "median_time_to_triage_s": 390.0,
    }
    assert [r["rule_id"] for r in data["rules"]][0] == "rule.a"  # type: ignore[attr-defined, index]


def test_compute_empty(session: Session) -> None:
    assert compute(session) == {
        "rules": [],
        "totals": {
            "findings": 0,
            "triaged": 0,
            "false_positives": 0,
            "fp_rate": None,
            "median_time_to_triage_s": None,
        },
    }


def test_api_endpoints(settings: Settings, sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        seed(s)
    client = TestClient(create_app(settings, sessions, FakeQueue()))
    assert client.get("/api/stats").json()["totals"]["findings"] == 6
    fps = client.get("/api/findings", params={"status": "false_positive"}).json()
    assert len(fps) == 2 and all(f["status"] == "false_positive" for f in fps)
    assert client.get("/api/findings", params={"limit": 9999}).status_code == 422
    assert client.get("/api/findings", params={"status": "nope"}).status_code == 422


def test_cors_allows_only_configured_origin(sessions: sessionmaker[Session]) -> None:
    client = TestClient(
        create_app(
            Settings(webhook_secret="s", cors_origins=("http://localhost:5173",)),
            sessions,
            FakeQueue(),
        )
    )
    ok = client.get("/api/stats", headers={"Origin": "http://localhost:5173"})
    bad = client.get("/api/stats", headers={"Origin": "https://evil.example"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers
