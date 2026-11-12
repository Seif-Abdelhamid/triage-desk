from __future__ import annotations

import base64
import json

import httpx
import pytest

from triage_desk.github_client import GitHubError, HttpGitHubClient, can_triage, check_repo


def make(handler) -> HttpGitHubClient:  # type: ignore[no-untyped-def]
    return HttpGitHubClient("tok", "https://api.test", transport=httpx.MockTransport(handler))


def test_sends_auth_and_api_version() -> None:
    seen: list[httpx.Request] = []

    def h(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=[])

    make(h).list_pr_files("acme/app", 3)
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert seen[0].headers["x-github-api-version"] == "2022-11-28"
    assert seen[0].url.path == "/repos/acme/app/pulls/3/files"


def test_paginates_files() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        page = int(req.url.params["page"])
        n = 100 if page == 1 else 5
        return httpx.Response(
            200,
            json=[
                {"filename": f"f{page}_{i}.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x"}
                for i in range(n)
            ],
        )

    assert len(make(h).list_pr_files("acme/app", 3)) == 105


def test_get_file_decodes_base64() -> None:
    def h(req: httpx.Request) -> httpx.Response:
        assert req.url.params["ref"] == "abc"
        return httpx.Response(
            200, json={"encoding": "base64", "content": base64.b64encode(b"print(1)\n").decode()}
        )

    assert make(h).get_file("acme/app", "src/a b.py", "abc") == b"print(1)\n"


def test_review_comment_payload() -> None:
    bodies: list[dict[str, object]] = []

    def h(req: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(req.content))
        return httpx.Response(201, json={"id": 99})

    cid = make(h).create_review_comment("acme/app", 3, "sha1", "a.py", 4, "hi")
    assert cid == 99
    assert bodies[0] == {
        "body": "hi",
        "commit_id": "sha1",
        "path": "a.py",
        "line": 4,
        "side": "RIGHT",
    }


@pytest.mark.parametrize(
    ("payload", "status", "expected"),
    [
        ({"permission": "write", "role_name": "write"}, 200, True),
        ({"permission": "read", "role_name": "triage"}, 200, True),
        ({"permission": "admin", "role_name": "admin"}, 200, True),
        ({"permission": "read", "role_name": "read"}, 200, False),
        ({"permission": "none"}, 200, False),
        ({"message": "Not Found"}, 404, False),
    ],
)
def test_can_triage(payload: dict[str, str], status: int, expected: bool) -> None:
    def h(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/repos/acme/app/collaborators/alice/permission"
        return httpx.Response(status, json=payload)

    assert can_triage(make(h), "acme/app", "alice") is expected


def test_weird_login_never_hits_api() -> None:
    def h(req: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("should not be called")

    assert make(h).collaborator_role("acme/app", "../../admin") is None


def test_server_errors_raise() -> None:
    with pytest.raises(GitHubError):
        make(lambda req: httpx.Response(500)).create_issue_comment("acme/app", 1, "x")


@pytest.mark.parametrize("bad", ["acme", "acme/app/x", "../etc", "a/..", "a b/c"])
def test_check_repo_rejects(bad: str) -> None:
    with pytest.raises(GitHubError):
        check_repo(bad)


def test_requires_token() -> None:
    with pytest.raises(GitHubError):
        HttpGitHubClient("")
