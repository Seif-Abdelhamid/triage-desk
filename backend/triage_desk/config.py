"""Settings read from the environment (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass(frozen=True)
class Settings:
    webhook_secret: str = field(default_factory=lambda: os.environ.get("GITHUB_WEBHOOK_SECRET", ""))
    github_token: str = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN", ""))
    github_api_url: str = field(
        default_factory=lambda: os.environ.get("GITHUB_API_URL", "https://api.github.com")
    )
    bot_login: str = field(default_factory=lambda: os.environ.get("BOT_LOGIN", ""))
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", "postgresql+psycopg://triage:triage@localhost:5432/triage"
        )
    )
    redis_url: str = field(
        default_factory=lambda: os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    )
    scan_queue: str = field(default_factory=lambda: os.environ.get("SCAN_QUEUE", "scans"))
    semgrep_config: str = field(
        default_factory=lambda: os.environ.get("SEMGREP_CONFIG", "p/default")
    )
    semgrep_timeout_s: int = field(default_factory=lambda: _int("SEMGREP_TIMEOUT_S", 300))
    max_files_per_scan: int = field(default_factory=lambda: _int("MAX_FILES_PER_SCAN", 200))
    max_file_bytes: int = field(default_factory=lambda: _int("MAX_FILE_BYTES", 1_000_000))
    max_webhook_bytes: int = field(default_factory=lambda: _int("MAX_WEBHOOK_BYTES", 5_000_000))
    replay_window_s: int = field(default_factory=lambda: _int("REPLAY_WINDOW_S", 7 * 24 * 3600))
    task_hard_limit_s: int = field(default_factory=lambda: _int("TASK_HARD_LIMIT_S", 900))
    target_tasks_per_worker: int = field(default_factory=lambda: _int("TARGET_TASKS_PER_WORKER", 2))
    cors_origins: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            o for o in os.environ.get("CORS_ORIGINS", "http://localhost:5173").split(",") if o
        )
    )


def get_settings() -> Settings:
    return Settings()
