"""Job bodies, free of Celery so they can be unit-tested with fakes.

``run_scan``      : fetch PR files -> semgrep -> upsert findings -> review comments
``handle_comment``: parse /triage -> RBAC -> status change + audit event -> reply
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import commands
from .config import Settings
from .diff import commentable_lines
from .github_client import GitHubClient, GitHubError, can_triage
from .models import (
    Finding,
    FindingStatus,
    Reachability,
    Repository,
    Scan,
    ScanStatus,
    TriageEvent,
    utcnow,
)
from .reachability import reaches
from .scanner import RawFinding, ScanError, Scanner, safe_relpath

log = logging.getLogger(__name__)
SYSTEM_ACTOR = "triage-desk"


def get_or_create_repo(session: Session, full_name: str) -> Repository:
    repo = session.scalar(select(Repository).where(Repository.full_name == full_name))
    if repo is None:
        repo = Repository(full_name=full_name)
        session.add(repo)
        session.flush()
    return repo


def fingerprint(rule_id: str, path: str, line_text: str, occurrence: int) -> str:
    """Stable across line shifts: keyed on the code text, not the line number."""
    norm = " ".join(line_text.split())
    raw = f"{rule_id}\0{path}\0{norm}\0{occurrence}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _comment_body(f: Finding) -> str:
    hint = ""
    if f.reachability_hint:
        hint = f"\n\n**Reachability hint:** {f.reachability_hint}"
    return (
        f"**Semgrep** `{f.rule_id}` ({f.severity})\n\n{f.message}{hint}\n\n"
        f"<sub>triage-desk finding #{f.id}. Reply with `/triage false-positive <reason>`, "
        f"`/triage accept-risk <reason>` or `/triage fixed`.</sub>"
    )


@dataclass
class ScanSummary:
    scan_id: int
    files_scanned: int
    findings: int
    new_comments: int
    suppressed: int
    skipped: bool = False
    error: str | None = None


def run_scan(
    session: Session,
    gh: GitHubClient,
    scanner: Scanner,
    settings: Settings,
    repo_name: str,
    pr: int,
    head_sha: str,
) -> ScanSummary:
    repo = get_or_create_repo(session, repo_name)
    existing = session.scalar(
        select(Scan).where(
            Scan.repo_id == repo.id,
            Scan.pr_number == pr,
            Scan.head_sha == head_sha,
            Scan.status == ScanStatus.done,
        )
    )
    if existing is not None:  # idempotent: a retried / replayed job does nothing
        return ScanSummary(existing.id, existing.files_scanned, 0, 0, 0, skipped=True)

    scan = Scan(repo_id=repo.id, pr_number=pr, head_sha=head_sha, status=ScanStatus.running)
    session.add(scan)
    session.flush()

    try:
        pr_files = [f for f in gh.list_pr_files(repo_name, pr) if f.status != "removed"]
        pr_files = pr_files[: settings.max_files_per_scan]
        sources: dict[str, str] = {}
        patches: dict[str, set[int]] = {}
        with tempfile.TemporaryDirectory(prefix="triage-desk-") as tmp:
            root = Path(tmp)
            for pf in pr_files:
                try:
                    rel = safe_relpath(pf.filename)
                    content = gh.get_file(repo_name, pf.filename, head_sha)
                except (ScanError, GitHubError) as exc:
                    log.warning("skipping %s: %s", pf.filename, exc)
                    continue
                if len(content) > settings.max_file_bytes:
                    continue
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content)
                sources[pf.filename] = content.decode("utf-8", errors="replace")
                patches[pf.filename] = commentable_lines(pf.patch)
            raw = scanner.scan(root, sorted(sources))
    except Exception as exc:
        scan.status = ScanStatus.failed
        scan.error = str(exc)[:2000]
        scan.finished_at = utcnow()
        session.flush()
        log.exception("scan %s failed", scan.id)
        return ScanSummary(scan.id, 0, 0, 0, 0, error=scan.error)

    new_comments = suppressed = 0
    occurrences: dict[tuple[str, str, str], int] = {}
    for rf in sorted(raw, key=lambda r: (r.path, r.line, r.rule_id)):
        if rf.path not in sources:
            continue
        lines = sources[rf.path].splitlines()
        text = lines[rf.line - 1] if 0 < rf.line <= len(lines) else ""
        key = (rf.rule_id, rf.path, " ".join(text.split()))
        occurrences[key] = occurrences.get(key, 0) + 1
        fp = fingerprint(rf.rule_id, rf.path, text, occurrences[key])
        finding = _upsert_finding(session, repo, scan, pr, fp, rf, sources[rf.path])

        if finding.status in (FindingStatus.false_positive, FindingStatus.accepted_risk):
            suppressed += 1
            continue
        if finding.status == FindingStatus.fixed:
            # Marked fixed but still detected at the new head: reopen, on the record.
            session.add(
                TriageEvent(
                    finding_id=finding.id,
                    repo_id=repo.id,
                    actor_login=SYSTEM_ACTOR,
                    action="reopen",
                    reason="still detected at " + head_sha[:12],
                    allowed=True,
                    previous_status=FindingStatus.fixed.value,
                    new_status=FindingStatus.open.value,
                )
            )
            finding.status = FindingStatus.open
        if finding.review_comment_id is None and rf.line in patches.get(rf.path, set()):
            finding.review_comment_id = gh.create_review_comment(
                repo_name, pr, head_sha, rf.path, rf.line, _comment_body(finding)
            )
            new_comments += 1

    scan.status = ScanStatus.done
    scan.files_scanned = len(sources)
    scan.finished_at = utcnow()
    session.flush()
    return ScanSummary(scan.id, len(sources), len(raw), new_comments, suppressed)


def _upsert_finding(
    session: Session, repo: Repository, scan: Scan, pr: int, fp: str, rf: RawFinding, source: str
) -> Finding:
    finding = session.scalar(
        select(Finding).where(Finding.repo_id == repo.id, Finding.fingerprint == fp)
    )
    if rf.path.endswith(".py"):
        result = reaches(source, rf.line)
        reach, hint = Reachability(result.label), result.as_hint()
    else:
        reach, hint = Reachability.not_applicable, None
    if finding is None:
        finding = Finding(
            repo_id=repo.id,
            fingerprint=fp,
            rule_id=rf.rule_id,
            path=rf.path,
            line=rf.line,
            severity=rf.severity,
            message=rf.message,
            pr_number=pr,
            first_scan_id=scan.id,
            last_scan_id=scan.id,
            reachability=reach,
            reachability_hint=hint,
            status=FindingStatus.open,
        )
        session.add(finding)
        session.flush()
    else:
        finding.line = rf.line
        finding.last_scan_id = scan.id
        finding.reachability = reach
        finding.reachability_hint = hint
    return finding


# ------------------------------------------------------------------ triage


@dataclass(frozen=True)
class CommentEvent:
    repo: str
    pr: int
    comment_id: int
    author: str
    author_type: str  # "User" | "Bot" | ...
    body: str
    in_reply_to_id: int | None = None  # set for review-thread replies
    is_review_comment: bool = False


def _reply(gh: GitHubClient, ev: CommentEvent, text: str) -> None:
    if ev.is_review_comment:
        gh.reply_to_review_comment(ev.repo, ev.pr, ev.in_reply_to_id or ev.comment_id, text)
    else:
        gh.create_issue_comment(ev.repo, ev.pr, text)


def handle_comment(session: Session, gh: GitHubClient, settings: Settings, ev: CommentEvent) -> str:
    """Returns a short outcome code (useful for tests and logs)."""
    if ev.author_type == "Bot" or (settings.bot_login and ev.author == settings.bot_login):
        return "ignored-bot"
    try:
        cmd = commands.parse(ev.body)
    except commands.CommandError as exc:
        _reply(gh, ev, f"Could not apply triage command: {exc}. {commands.USAGE}")
        return "usage"
    if cmd is None:
        return "not-a-command"

    repo = get_or_create_repo(session, ev.repo)
    if (
        session.scalar(
            select(TriageEvent.id).where(
                TriageEvent.repo_id == repo.id, TriageEvent.github_comment_id == ev.comment_id
            )
        )
        is not None
    ):
        return "duplicate"

    finding: Finding | None = None
    if cmd.finding_id is not None:
        finding = session.get(Finding, cmd.finding_id)
    elif ev.in_reply_to_id is not None:
        finding = session.scalar(
            select(Finding).where(Finding.review_comment_id == ev.in_reply_to_id)
        )
    # Never let a command in repo A touch a finding that belongs to repo B.
    if finding is not None and finding.repo_id != repo.id:
        finding = None

    allowed = can_triage(gh, ev.repo, ev.author)
    event = TriageEvent(
        finding_id=finding.id if finding else None,
        repo_id=repo.id,
        actor_login=ev.author,
        action=cmd.action,
        reason=cmd.reason,
        allowed=allowed,
        previous_status=finding.status.value if finding else None,
        github_comment_id=ev.comment_id,
    )
    if not allowed:
        session.add(event)  # denied attempts are audited too
        session.flush()
        _reply(
            gh,
            ev,
            "Only repository collaborators with triage or write access can "
            "triage findings. This attempt was recorded.",
        )
        return "denied"
    if finding is None:
        event.action = f"{cmd.action}:no-finding"
        session.add(event)
        session.flush()
        _reply(gh, ev, f"No triage-desk finding matches this comment. {commands.USAGE}")
        return "no-finding"

    finding.status = cmd.new_status
    if finding.first_triaged_at is None:
        finding.first_triaged_at = utcnow()
    event.new_status = cmd.new_status.value
    session.add(event)
    session.flush()
    _reply(gh, ev, f"Marked finding #{finding.id} as **{cmd.new_status.value}** (by {ev.author}).")
    return "applied"
