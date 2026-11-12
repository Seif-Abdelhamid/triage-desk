from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from triage_desk.github_client import PrFile
from triage_desk.jobs import CommentEvent
from triage_desk.scanner import RawFinding


@dataclass
class FakeGitHub:
    files: dict[str, tuple[str, str | None]] = field(
        default_factory=dict
    )  # path -> (content, patch)
    roles: dict[str, str] = field(default_factory=dict)
    review_comments: list[dict[str, object]] = field(default_factory=list)
    replies: list[dict[str, object]] = field(default_factory=list)
    issue_comments: list[dict[str, object]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    _next_id: int = 1000

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def list_pr_files(self, repo: str, pr: int) -> list[PrFile]:
        out = [PrFile(p, "modified", patch) for p, (_, patch) in self.files.items()]
        return out + [PrFile(p, "removed", None) for p in self.removed]

    def get_file(self, repo: str, path: str, ref: str) -> bytes:
        return self.files[path][0].encode()

    def create_review_comment(
        self, repo: str, pr: int, commit_sha: str, path: str, line: int, body: str
    ) -> int:
        cid = self._id()
        self.review_comments.append(
            {"id": cid, "path": path, "line": line, "body": body, "sha": commit_sha}
        )
        return cid

    def reply_to_review_comment(self, repo: str, pr: int, comment_id: int, body: str) -> int:
        self.replies.append({"to": comment_id, "body": body})
        return self._id()

    def create_issue_comment(self, repo: str, pr: int, body: str) -> int:
        self.issue_comments.append({"body": body})
        return self._id()

    def collaborator_role(self, repo: str, login: str) -> str | None:
        return self.roles.get(login)


@dataclass
class FakeScanner:
    findings: list[RawFinding] = field(default_factory=list)
    seen: list[list[str]] = field(default_factory=list)
    roots: list[set[str]] = field(default_factory=list)

    def scan(self, root: Path, files: list[str]) -> list[RawFinding]:
        self.seen.append(files)
        self.roots.append({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()})
        return list(self.findings)


@dataclass
class FakeQueue:
    scans: list[tuple[str, int, str]] = field(default_factory=list)
    comments: list[CommentEvent] = field(default_factory=list)

    def enqueue_scan(self, repo: str, pr: int, head_sha: str) -> None:
        self.scans.append((repo, pr, head_sha))

    def enqueue_comment(self, event: CommentEvent) -> None:
        self.comments.append(event)
