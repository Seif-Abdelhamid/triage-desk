"""How the API hands work to the worker. A Protocol so tests can capture jobs."""

from __future__ import annotations

from dataclasses import asdict
from typing import Protocol

from .jobs import CommentEvent


class JobQueue(Protocol):
    def enqueue_scan(self, repo: str, pr: int, head_sha: str) -> None: ...

    def enqueue_comment(self, event: CommentEvent) -> None: ...


class CeleryJobQueue:
    def enqueue_scan(self, repo: str, pr: int, head_sha: str) -> None:
        from .worker import scan_pull_request

        scan_pull_request.delay(repo, pr, head_sha)

    def enqueue_comment(self, event: CommentEvent) -> None:
        from .worker import triage_comment

        triage_comment.delay(asdict(event))
