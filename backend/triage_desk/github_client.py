"""The slice of the GitHub REST API the bot needs, behind a Protocol.

Production uses :class:`HttpGitHubClient` (httpx). Tests use an in-memory
fake (tests/fakes.py) so no network or token is needed.

Token scope: a fine-grained token or GitHub App installation token limited
to the installed repositories with *Pull requests: read & write*,
*Contents: read* and *Metadata: read*. Nothing else is required.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote

import httpx

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}(\[bot\])?$")
TRIAGE_ROLES = frozenset({"admin", "maintain", "write", "triage"})


class GitHubError(RuntimeError):
    pass


@dataclass(frozen=True)
class PrFile:
    filename: str
    status: str  # added | modified | removed | renamed | ...
    patch: str | None


class GitHubClient(Protocol):
    def list_pr_files(self, repo: str, pr: int) -> list[PrFile]: ...

    def get_file(self, repo: str, path: str, ref: str) -> bytes: ...

    def create_review_comment(
        self, repo: str, pr: int, commit_sha: str, path: str, line: int, body: str
    ) -> int: ...

    def reply_to_review_comment(self, repo: str, pr: int, comment_id: int, body: str) -> int: ...

    def create_issue_comment(self, repo: str, pr: int, body: str) -> int: ...

    def collaborator_role(self, repo: str, login: str) -> str | None:
        """Role name (admin/maintain/write/triage/read) or None if not a collaborator."""
        ...


def can_triage(gh: GitHubClient, repo: str, login: str) -> bool:
    return gh.collaborator_role(repo, login) in TRIAGE_ROLES


def check_repo(repo: str) -> str:
    if not _REPO_RE.match(repo) or ".." in repo:
        raise GitHubError(f"invalid repository name: {repo!r}")
    return repo


class HttpGitHubClient:
    def __init__(
        self,
        token: str,
        base_url: str = "https://api.github.com",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token:
            raise GitHubError("GITHUB_TOKEN is not set")
        self._http = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "triage-desk",
            },
            timeout=20.0,
            transport=transport,
        )

    def _req(self, method: str, url: str, **kw: object) -> httpx.Response:
        resp = self._http.request(method, url, **kw)  # type: ignore[arg-type]
        if resp.status_code >= 400 and resp.status_code != 404:
            raise GitHubError(f"{method} {url} -> {resp.status_code}")
        return resp

    def list_pr_files(self, repo: str, pr: int) -> list[PrFile]:
        files: list[PrFile] = []
        page = 1
        while page <= 10:  # GitHub caps this endpoint at 3000 files / 30 pages
            resp = self._req(
                "GET",
                f"/repos/{check_repo(repo)}/pulls/{pr}/files",
                params={"per_page": 100, "page": page},
            )
            batch = resp.json()
            files += [PrFile(f["filename"], f["status"], f.get("patch")) for f in batch]
            if len(batch) < 100:
                break
            page += 1
        return files

    def get_file(self, repo: str, path: str, ref: str) -> bytes:
        resp = self._req(
            "GET", f"/repos/{check_repo(repo)}/contents/{quote(path)}", params={"ref": ref}
        )
        if resp.status_code == 404:
            raise GitHubError(f"file not found: {path}")
        data = resp.json()
        if data.get("encoding") != "base64":
            raise GitHubError(f"unexpected encoding for {path}")
        return base64.b64decode(data["content"])

    def create_review_comment(
        self, repo: str, pr: int, commit_sha: str, path: str, line: int, body: str
    ) -> int:
        resp = self._req(
            "POST",
            f"/repos/{check_repo(repo)}/pulls/{pr}/comments",
            json={
                "body": body,
                "commit_id": commit_sha,
                "path": path,
                "line": line,
                "side": "RIGHT",
            },
        )
        return int(resp.json()["id"])

    def reply_to_review_comment(self, repo: str, pr: int, comment_id: int, body: str) -> int:
        resp = self._req(
            "POST",
            f"/repos/{check_repo(repo)}/pulls/{pr}/comments/{comment_id}/replies",
            json={"body": body},
        )
        return int(resp.json()["id"])

    def create_issue_comment(self, repo: str, pr: int, body: str) -> int:
        resp = self._req(
            "POST", f"/repos/{check_repo(repo)}/issues/{pr}/comments", json={"body": body}
        )
        return int(resp.json()["id"])

    def collaborator_role(self, repo: str, login: str) -> str | None:
        if not _LOGIN_RE.match(login):
            return None
        resp = self._req("GET", f"/repos/{check_repo(repo)}/collaborators/{login}/permission")
        if resp.status_code == 404:
            return None
        data = resp.json()
        role = data.get("role_name") or data.get("permission")
        return str(role) if role and role != "none" else None
