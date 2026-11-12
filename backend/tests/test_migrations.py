from __future__ import annotations

import os
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from alembic import command
from triage_desk.models import Base

BACKEND = Path(__file__).resolve().parents[1]


def cfg(url: str) -> Config:
    c = Config(str(BACKEND / "alembic.ini"))
    c.set_main_option("script_location", str(BACKEND / "alembic"))
    c.set_main_option("sqlalchemy.url", url)
    return c


def test_migration_matches_models_sqlite(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'm.db'}"
    command.upgrade(cfg(url), "head")
    insp = inspect(create_engine(url))
    tables = set(insp.get_table_names()) - {"alembic_version"}
    assert tables == set(Base.metadata.tables)
    for name, table in Base.metadata.tables.items():
        assert {c["name"] for c in insp.get_columns(name)} == {c.name for c in table.columns}
    command.downgrade(cfg(url), "base")


@pytest.mark.skipif("TEST_POSTGRES_URL" not in os.environ, reason="TEST_POSTGRES_URL not set")
def test_audit_trail_is_append_only_on_postgres() -> None:
    url = os.environ["TEST_POSTGRES_URL"]
    command.downgrade(cfg(url), "base")
    command.upgrade(cfg(url), "head")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO repositories (full_name) VALUES ('acme/app')"))
        conn.execute(
            text(
                "INSERT INTO triage_events (repo_id, actor_login, action, allowed) "
                "SELECT id, 'alice', 'fixed', true FROM repositories"
            )
        )
    for stmt in ("UPDATE triage_events SET actor_login = 'mallory'", "DELETE FROM triage_events"):
        with pytest.raises(Exception, match="append-only"), engine.begin() as conn:
            conn.execute(text(stmt))
    command.downgrade(cfg(url), "base")
