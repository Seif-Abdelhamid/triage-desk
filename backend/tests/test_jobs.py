from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from triage_desk.config import Settings
from triage_desk.jobs import CommentEvent, handle_comment, run_scan
from triage_desk.models import Finding, FindingStatus, Reachability, Scan, ScanStatus, TriageEvent
from triage_desk.scanner import RawFinding

from .fakes import FakeGitHub, FakeScanner

APP_PY = """from flask import request
import subprocess

def run():
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)

def safe():
    subprocess.run("ls", shell=True)
"""
PATCH = "@@ -0,0 +1,9 @@\n" + "\n".join("+" + ln for ln in APP_PY.splitlines())
SHA = "b" * 40
RULE = "python.lang.security.audit.subprocess-shell-true"


def setup(lines: tuple[int, ...] = (6, 9)) -> tuple[FakeGitHub, FakeScanner]:
    gh = FakeGitHub(
        files={"src/app.py": (APP_PY, PATCH)},
        removed=["old.py"],
        roles={"alice": "write", "tri": "triage", "rob": "read"},
    )
    scanner = FakeScanner(
        [RawFinding(RULE, "src/app.py", ln, "ERROR", "shell=True") for ln in lines]
    )
    return gh, scanner


def scan(
    session: Session, gh: FakeGitHub, scanner: FakeScanner, settings: Settings, sha: str = SHA
):
    out = run_scan(session, gh, scanner, settings, "acme/app", 7, sha)
    session.commit()
    return out


def test_scan_creates_findings_and_comments(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    summary = scan(session, gh, scanner, settings)
    assert summary.findings == 2 and summary.new_comments == 2
    assert scanner.seen == [["src/app.py"]]  # removed files are not fetched or scanned
    assert scanner.roots == [{"src/app.py"}]
    findings = session.scalars(select(Finding).order_by(Finding.line)).all()
    assert [f.reachability for f in findings] == [Reachability.tainted, Reachability.not_tainted]
    assert "tainted input reaches this line" in str(gh.review_comments[0]["body"])
    assert all(c["sha"] == SHA for c in gh.review_comments)
    assert session.scalar(select(Scan)).status == ScanStatus.done  # type: ignore[union-attr]


def test_same_head_sha_is_idempotent(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    again = scan(session, gh, scanner, settings)
    assert again.skipped
    assert len(gh.review_comments) == 2


def test_new_push_does_not_duplicate_comments(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    second = scan(session, gh, scanner, settings, sha="c" * 40)
    assert second.new_comments == 0
    assert session.scalar(select(Finding).where(Finding.line == 6)).last_scan_id == second.scan_id  # type: ignore[union-attr]


def test_lines_outside_diff_are_not_commented(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    gh.files["src/app.py"] = (APP_PY, "@@ -1,2 +1,2 @@\n-x\n+cmd\n context")
    summary = scan(session, gh, scanner, settings)
    assert summary.findings == 2 and summary.new_comments == 0


def test_unsafe_paths_are_never_written(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    gh.files["../../etc/evil.py"] = ("x = 1\n", None)
    scan(session, gh, scanner, settings)
    assert scanner.seen == [["src/app.py"]]


def test_scanner_failure_marks_scan_failed(session: Session, settings: Settings) -> None:
    from triage_desk.scanner import ScanError

    class Boom(FakeScanner):
        def scan(self, root, files):  # type: ignore[no-untyped-def]
            raise ScanError("semgrep exited 2")

    gh, _ = setup()
    summary = scan(session, gh, Boom(), settings)
    assert summary.error == "semgrep exited 2"
    assert session.scalar(select(Scan)).status == ScanStatus.failed  # type: ignore[union-attr]


def reply(
    body: str, author: str = "alice", to: int | None = None, cid: int = 1, author_type: str = "User"
) -> CommentEvent:
    return CommentEvent(
        repo="acme/app",
        pr=7,
        comment_id=cid,
        author=author,
        author_type=author_type,
        body=body,
        in_reply_to_id=to,
        is_review_comment=to is not None,
    )


def first_comment_id(gh: FakeGitHub) -> int:
    return int(gh.review_comments[0]["id"])  # type: ignore[call-overload]


def test_collaborator_marks_false_positive(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    out = handle_comment(
        session,
        gh,
        settings,
        reply("/triage false-positive cmd is validated upstream", to=first_comment_id(gh)),
    )
    assert out == "applied"
    f = session.scalar(select(Finding).where(Finding.line == 6))
    assert f is not None and f.status == FindingStatus.false_positive
    assert f.first_triaged_at is not None
    ev = session.scalar(select(TriageEvent))
    assert ev is not None
    assert (ev.actor_login, ev.action, ev.allowed, ev.previous_status, ev.new_status) == (
        "alice",
        "false-positive",
        True,
        "open",
        "false_positive",
    )
    assert ev.reason == "cmd is validated upstream"
    assert "false_positive" in str(gh.replies[-1]["body"])


def test_triage_role_is_enough(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    assert (
        handle_comment(
            session, gh, settings, reply("/triage fixed", author="tri", to=first_comment_id(gh))
        )
        == "applied"
    )


def test_non_collaborator_denied_and_audited(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    for i, who in enumerate(["mallory", "rob"]):  # outsider, read-only
        out = handle_comment(
            session,
            gh,
            settings,
            reply("/triage accept-risk trust me", author=who, to=first_comment_id(gh), cid=10 + i),
        )
        assert out == "denied"
    f = session.scalar(select(Finding).where(Finding.line == 6))
    assert f is not None and f.status == FindingStatus.open
    events = session.scalars(select(TriageEvent)).all()
    assert [(e.actor_login, e.allowed) for e in events] == [("mallory", False), ("rob", False)]


def test_bot_comments_ignored(session: Session, settings: Settings) -> None:
    gh, _ = setup()
    assert (
        handle_comment(session, gh, settings, reply("/triage fixed", author_type="Bot"))
        == "ignored-bot"
    )
    assert (
        handle_comment(session, gh, settings, reply("/triage fixed", author="triage-desk-bot"))
        == "ignored-bot"
    )


def test_redelivered_comment_is_not_applied_twice(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    ev = reply("/triage fixed", to=first_comment_id(gh), cid=77)
    assert handle_comment(session, gh, settings, ev) == "applied"
    assert handle_comment(session, gh, settings, ev) == "duplicate"


def test_explicit_id_in_issue_comment(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    f = session.scalar(select(Finding).where(Finding.line == 9))
    assert f is not None
    assert (
        handle_comment(
            session, gh, settings, reply(f"/triage accept-risk #{f.id} constant command")
        )
        == "applied"
    )
    assert f.status == FindingStatus.accepted_risk
    assert gh.issue_comments  # top-level reply, not a thread reply


def test_command_cannot_cross_repositories(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    f = session.scalar(select(Finding).where(Finding.line == 9))
    assert f is not None
    other = CommentEvent(
        repo="evil/other",
        pr=1,
        comment_id=5,
        author="alice",
        author_type="User",
        body=f"/triage fixed #{f.id}",
    )
    assert handle_comment(session, gh, settings, other) == "no-finding"
    assert f.status == FindingStatus.open


def test_malformed_command_gets_usage(session: Session, settings: Settings) -> None:
    gh, _ = setup()
    assert handle_comment(session, gh, settings, reply("/triage false-positive")) == "usage"
    assert "Usage" in str(gh.issue_comments[-1]["body"])


def test_triaged_false_positive_is_suppressed_on_rescan(
    session: Session, settings: Settings
) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    handle_comment(
        session, gh, settings, reply("/triage false-positive validated", to=first_comment_id(gh))
    )
    session.commit()
    summary = scan(session, gh, scanner, settings, sha="d" * 40)
    assert summary.suppressed == 1


def test_fixed_but_still_detected_reopens(session: Session, settings: Settings) -> None:
    gh, scanner = setup()
    scan(session, gh, scanner, settings)
    handle_comment(session, gh, settings, reply("/triage fixed", to=first_comment_id(gh)))
    session.commit()
    scan(session, gh, scanner, settings, sha="e" * 40)
    f = session.scalar(select(Finding).where(Finding.line == 6))
    assert f is not None and f.status == FindingStatus.open
    reopen = session.scalar(select(TriageEvent).where(TriageEvent.action == "reopen"))
    assert reopen is not None and reopen.actor_login == "triage-desk"
