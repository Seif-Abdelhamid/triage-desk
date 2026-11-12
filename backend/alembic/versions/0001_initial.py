"""initial schema: repositories, deliveries, scans, findings, triage audit trail

Revision ID: 0001
Revises:
Create Date: 2026-11-12
"""

import sqlalchemy as sa

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

finding_status = sa.Enum("open", "false_positive", "accepted_risk", "fixed", name="finding_status")
reachability = sa.Enum("tainted", "not_tainted", "unknown", "not_applicable", name="reachability")
scan_status = sa.Enum("queued", "running", "done", "failed", name="scan_status")


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("full_name", sa.String(200), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "webhook_deliveries",
        sa.Column("delivery_id", sa.String(64), primary_key=True),
        sa.Column("event", sa.String(64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_webhook_deliveries_received_at", "webhook_deliveries", ["received_at"])
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("repo_id", sa.Integer, sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("pr_number", sa.Integer, nullable=False),
        sa.Column("head_sha", sa.String(40), nullable=False),
        sa.Column("status", scan_status),
        sa.Column("files_scanned", sa.Integer),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("repo_id", sa.Integer, sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("rule_id", sa.String(300), nullable=False),
        sa.Column("path", sa.String(1000), nullable=False),
        sa.Column("line", sa.Integer, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("pr_number", sa.Integer, nullable=False),
        sa.Column("first_scan_id", sa.Integer, sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("last_scan_id", sa.Integer, sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("review_comment_id", sa.BigInteger, unique=True),
        sa.Column("reachability", reachability),
        sa.Column("reachability_hint", sa.Text),
        sa.Column("status", finding_status),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("first_triaged_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("repo_id", "fingerprint", name="uq_finding_fingerprint"),
    )
    op.create_index("ix_findings_rule_id", "findings", ["rule_id"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_table(
        "triage_events",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("finding_id", sa.Integer, sa.ForeignKey("findings.id")),
        sa.Column("repo_id", sa.Integer, sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("actor_login", sa.String(100), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(500)),
        sa.Column("allowed", sa.Boolean, nullable=False),
        sa.Column("previous_status", sa.String(32)),
        sa.Column("new_status", sa.String(32)),
        sa.Column("github_comment_id", sa.BigInteger),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_triage_events_finding_id", "triage_events", ["finding_id"])

    if op.get_bind().dialect.name == "postgresql":
        # The audit trail is append-only, enforced by the database, not by app code.
        op.execute(
            """
            CREATE FUNCTION triage_events_append_only() RETURNS trigger AS $$
            BEGIN
              RAISE EXCEPTION 'triage_events is append-only';
            END;
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            """
            CREATE TRIGGER triage_events_no_update_delete
            BEFORE UPDATE OR DELETE ON triage_events
            FOR EACH ROW EXECUTE FUNCTION triage_events_append_only();
            """
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS triage_events_no_update_delete ON triage_events")
        op.execute("DROP FUNCTION IF EXISTS triage_events_append_only()")
    op.drop_table("triage_events")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("webhook_deliveries")
    op.drop_table("repositories")
    for enum in (finding_status, reachability, scan_status):
        enum.drop(op.get_bind(), checkfirst=True)
