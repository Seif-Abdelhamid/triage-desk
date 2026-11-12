"""Dashboard aggregates: findings per rule, false-positive rate, time-to-triage."""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Finding, FindingStatus


@dataclass
class RuleStats:
    rule_id: str
    findings: int = 0
    open: int = 0
    triaged: int = 0
    false_positives: int = 0
    accepted_risk: int = 0
    fixed: int = 0
    fp_rate: float | None = None
    median_time_to_triage_s: float | None = None


def _seconds(start: datetime, end: datetime) -> float:
    # SQLite returns naive datetimes; both sides are UTC by construction.
    if (start.tzinfo is None) != (end.tzinfo is None):
        start, end = start.replace(tzinfo=None), end.replace(tzinfo=None)
    return (end - start).total_seconds()


def compute(session: Session, repo_id: int | None = None) -> dict[str, object]:
    """FP rate = false positives / triaged findings (open findings have no verdict yet)."""
    q = select(Finding.rule_id, Finding.status, Finding.created_at, Finding.first_triaged_at)
    if repo_id is not None:
        q = q.where(Finding.repo_id == repo_id)
    rules: dict[str, RuleStats] = {}
    durations: dict[str, list[float]] = {}
    all_durations: list[float] = []
    for rule_id, status, created, triaged_at in session.execute(q):
        rs = rules.setdefault(rule_id, RuleStats(rule_id))
        rs.findings += 1
        if status == FindingStatus.open:
            rs.open += 1
        else:
            rs.triaged += 1
            rs.false_positives += status == FindingStatus.false_positive
            rs.accepted_risk += status == FindingStatus.accepted_risk
            rs.fixed += status == FindingStatus.fixed
        if triaged_at is not None:
            d = _seconds(created, triaged_at)
            durations.setdefault(rule_id, []).append(d)
            all_durations.append(d)
    for rule_id, rs in rules.items():
        rs.fp_rate = round(rs.false_positives / rs.triaged, 4) if rs.triaged else None
        if durations.get(rule_id):
            rs.median_time_to_triage_s = statistics.median(durations[rule_id])
    ordered = sorted(rules.values(), key=lambda r: (-r.findings, r.rule_id))
    total = sum(r.findings for r in ordered)
    triaged = sum(r.triaged for r in ordered)
    fps = sum(r.false_positives for r in ordered)
    return {
        "rules": [r.__dict__ for r in ordered],
        "totals": {
            "findings": total,
            "triaged": triaged,
            "false_positives": fps,
            "fp_rate": round(fps / triaged, 4) if triaged else None,
            "median_time_to_triage_s": statistics.median(all_durations) if all_durations else None,
        },
    }
