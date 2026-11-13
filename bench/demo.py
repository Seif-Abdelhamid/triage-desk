#!/usr/bin/env python3
"""Local demo helpers: drive the real job code without a webhook or Celery.

    python bench/demo.py load-bench  --db /tmp/td-demo/triage.db
        run_scan on every Python file of the three benchmark apps (real Semgrep,
        GitHub faked), so the dashboard shows real findings.

    GITHUB_TOKEN=... python bench/demo.py scan-pr --db ... --repo owner/name --pr 1
        run_scan against the real GitHub API: fetches the PR files, runs Semgrep
        and posts inline review comments.

    GITHUB_TOKEN=... python bench/demo.py triage --db ... --repo owner/name --pr 1 --comment ID
        fetches a real review comment, turns it into the webhook event shape the
        API would build (main._comment_event) and runs jobs.handle_comment, which
        checks the author's role, records the decision and replies on GitHub.

    python bench/demo.py serve --db ...      # FastAPI app on 127.0.0.1:8000

The token is read from the environment only and never written anywhere.

Status: ``load-bench`` and ``serve`` produced docs/images/dashboard.png.
``scan-pr`` and ``triage`` have NOT yet been run against the live GitHub API
(creating the public demo repository was not done), so treat them as untested.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH.parent / "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from triage_desk.config import Settings
from triage_desk.models import Base
from triage_desk.scanner import SemgrepCli


def sessions_for(db: Path) -> sessionmaker[Session]:
    db.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def load_bench(args: argparse.Namespace) -> None:
    from tests.fakes import FakeGitHub
    from triage_desk.jobs import run_scan

    semgrep = json.loads((BENCH / "results" / "semgrep.json").read_text())
    settings = Settings(webhook_secret="demo", github_token="x", bot_login="bench-bot")
    make = sessions_for(args.db)
    for i, (app, meta) in enumerate(semgrep["apps"].items()):
        files = {}
        for rel in meta["scanned_paths"]:
            text = (args.workdir / app / rel).read_text("utf-8", errors="replace")
            n = len(text.splitlines())
            files[rel] = (
                text,
                f"@@ -0,0 +1,{n} @@\n" + "\n".join("+" + x for x in text.splitlines()),
            )
        with make.begin() as s:
            out = run_scan(
                s,
                FakeGitHub(files=files, _next_id=(i + 1) * 100_000),
                SemgrepCli(str(args.rules)),
                settings,
                f"bench/{app}",
                1,
                meta["sha"],
            )
        print(app, out)


def _gh():  # type: ignore[no-untyped-def]
    from triage_desk.github_client import HttpGitHubClient

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SystemExit("set GITHUB_TOKEN in the environment")
    return HttpGitHubClient(token)


def scan_pr(args: argparse.Namespace) -> None:
    from triage_desk.jobs import run_scan

    gh = _gh()
    pr = gh._req("GET", f"/repos/{args.repo}/pulls/{args.pr}").json()
    settings = Settings(webhook_secret="demo", github_token="x", bot_login="")
    with sessions_for(args.db).begin() as s:
        out = run_scan(
            s, gh, SemgrepCli(str(args.rules)), settings, args.repo, args.pr, pr["head"]["sha"]
        )
    print(out)


def triage(args: argparse.Namespace) -> None:
    from triage_desk.jobs import handle_comment
    from triage_desk.main import _comment_event

    gh = _gh()
    comment = gh._req("GET", f"/repos/{args.repo}/pulls/comments/{args.comment}").json()
    payload = {
        "action": "created",
        "repository": {"full_name": args.repo},
        "pull_request": {"number": args.pr},
        "comment": comment,
    }
    ev = _comment_event("pull_request_review_comment", payload)
    if ev is None:
        raise SystemExit("not a /triage review comment")
    # bot_login is empty: in this demo the bot and the reviewer are the same account.
    settings = Settings(webhook_secret="demo", github_token="x", bot_login="")
    with sessions_for(args.db).begin() as s:
        print(handle_comment(s, gh, settings, ev))


def serve(args: argparse.Namespace) -> None:
    import uvicorn
    from tests.fakes import FakeQueue
    from triage_desk.main import create_app

    app = create_app(Settings(webhook_secret="demo"), sessions_for(args.db), FakeQueue())
    uvicorn.run(app, host="127.0.0.1", port=8000)


def main() -> None:
    # SemgrepCli resolves "semgrep" on PATH; prefer the one next to this interpreter.
    os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["load-bench", "scan-pr", "triage", "serve"])
    ap.add_argument("--db", type=Path, required=True)
    ap.add_argument("--workdir", type=Path, default=Path("/tmp/bench"))
    ap.add_argument("--rules", default="p/python")
    ap.add_argument("--repo")
    ap.add_argument("--pr", type=int)
    ap.add_argument("--comment", type=int)
    args = ap.parse_args()
    {"load-bench": load_bench, "scan-pr": scan_pr, "triage": triage, "serve": serve}[args.cmd](args)


if __name__ == "__main__":
    main()
