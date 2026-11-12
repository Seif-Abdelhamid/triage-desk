from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from triage_desk.config import Settings
from triage_desk.models import Base


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    """In-memory SQLite by default; set TEST_DATABASE_URL to run on PostgreSQL."""
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        engine = create_engine(url)
    else:
        engine = create_engine(
            "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def session(sessions: sessionmaker[Session]) -> Iterator[Session]:
    s = sessions()
    yield s
    s.close()


@pytest.fixture
def settings() -> Settings:
    return Settings(webhook_secret="test-secret", github_token="x", bot_login="triage-desk-bot")
