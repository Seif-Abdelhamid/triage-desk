"""Database schema. Mirrors alembic/versions/0001_initial.py."""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class FindingStatus(enum.StrEnum):
    open = "open"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    fixed = "fixed"


class Reachability(enum.StrEnum):
    tainted = "tainted"
    not_tainted = "not_tainted"
    unknown = "unknown"
    not_applicable = "not_applicable"  # non-Python file


class ScanStatus(enum.StrEnum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebhookDelivery(Base):
    """Replay protection: every accepted X-GitHub-Delivery id, once."""

    __tablename__ = "webhook_deliveries"

    delivery_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), default=ScanStatus.queued
    )
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("repo_id", "fingerprint", name="uq_finding_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    line: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    first_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    last_scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    review_comment_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    reachability: Mapped[Reachability] = mapped_column(
        Enum(Reachability, name="reachability"), default=Reachability.not_applicable
    )
    reachability_hint: Mapped[str | None] = mapped_column(Text)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"), default=FindingStatus.open, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    first_triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    events: Mapped[list[TriageEvent]] = relationship(back_populates="finding")


class TriageEvent(Base):
    """Append-only audit trail. On PostgreSQL a trigger rejects UPDATE/DELETE."""

    __tablename__ = "triage_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), index=True)
    repo_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    actor_login: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(500))
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(32))
    new_status: Mapped[str | None] = mapped_column(String(32))
    github_comment_id: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    finding: Mapped[Finding | None] = relationship(back_populates="events")
