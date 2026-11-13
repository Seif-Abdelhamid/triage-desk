#!/usr/bin/env python3
"""Reproducible benchmark for triage-desk.

One command reproduces every number in BENCHMARK.md:

    python bench/run_benchmark.py            # from projects/triage-desk, inside the venv

It needs the backend installed (``pip install -e "backend[dev]" semgrep pytest-cov``),
``semgrep`` next to the interpreter, ``git``, ``curl``-free network access to
github.com and semgrep.dev, and (for the dashboard step) ``npm``.

Steps
-----
1. tests     backend ``pytest --cov=triage_desk``; dashboard ``vitest run --coverage``
2. clone     three intentionally vulnerable Python apps at pinned commits
3. semgrep   ``semgrep scan --config p/python --json --metrics=off`` on each app
4. reach     triage-desk's reachability hint on every finding
5. accuracy  precision / recall of the ``tainted`` label against bench/labels.csv
6. scan      ``jobs.run_scan`` end to end (GitHub faked, real Semgrep) on 10/25/50 files
7. webhook   HMAC verification and replay rejection timings

Raw results go to bench/results/*.json. Nothing here estimates a number: if a
step cannot run, the script stops with an error instead of writing a guess.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

BENCH = Path(__file__).resolve().parent
PROJECT = BENCH.parent
BACKEND = PROJECT / "backend"
DASHBOARD = PROJECT / "dashboard"
RESULTS = BENCH / "results"
LABELS = BENCH / "labels.csv"

APPS = [
    {
        "name": "pygoat",
        "url": "https://github.com/adeyosemanputra/pygoat",
        "sha": "2aa4cc14f251e4a780e94e200aed6b36a5b15c21",
    },
    {
        "name": "Vulnerable-Flask-App",
        "url": "https://github.com/we45/Vulnerable-Flask-App",
        "sha": "b6a4f97afd466e83e1f60781494252dec1c37039",
    },
    {
        "name": "dvpwa",
        "url": "https://github.com/anxolerd/dvpwa",
        "sha": "4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756",
    },
]
RULESET = "p/python"
RULESET_URL = "https://semgrep.dev/c/p/python"
# sha256 of the p/python snapshot the published results were produced with.
RULESET_SHA256 = "de5bc79d074c3b4146338a0bf95830406f169bd91ac590a2f1ef111f162e23f5"
SAMPLE_SIZE = 40
SAMPLE_SEED = 0
RUNS = 5
BATCHES = (10, 25, 50)
WEBHOOK_N = 10_000

sys.path.insert(0, str(BACKEND))  # for tests.fakes, exactly as the test suite imports it


def log(msg: str) -> None:
    print(f"[bench] {msg}", flush=True)


def run(cmd: list[str], cwd: Path | None = None, **kw: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False, **kw)


def write(name: str, data: object) -> None:
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / name).write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    log(f"wrote bench/results/{name}")


def p95(xs: list[float]) -> float:
    """Nearest-rank 95th percentile."""
    s = sorted(xs)
    return s[math.ceil(0.95 * len(s)) - 1]


def env_with_venv() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    return env


# ------------------------------------------------------------------ environment


def environment() -> dict[str, Any]:
    def out(cmd: list[str]) -> str:
        try:
            r = run(cmd, env=env_with_venv())
            return (r.stdout or r.stderr).strip()
        except FileNotFoundError:
            return "not found"

    import importlib.metadata as md

    pkgs = {}
    for p in (
        "triage-desk",
        "semgrep",
        "pytest",
        "pytest-cov",
        "coverage",
        "sqlalchemy",
        "fastapi",
        "httpx",
    ):
        try:
            pkgs[p] = md.version(p)
        except md.PackageNotFoundError:
            pkgs[p] = None
    return {
        "cpu": out(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "cores": os.cpu_count(),
        "memory_bytes": int(out(["sysctl", "-n", "hw.memsize"]) or 0)
        if sys.platform == "darwin"
        else None,
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "semgrep_cli": out(["semgrep", "--version"]),
        "node": out(["node", "--version"]),
        "packages": pkgs,
        "project_commit": out(["git", "-C", str(PROJECT), "rev-parse", "HEAD"]),
    }


# ------------------------------------------------------------------ 1. tests


def step_tests() -> dict[str, Any]:
    log("backend: pytest --cov=triage_desk")
    r = run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--cov=triage_desk",
            "--cov-report=json:/dev/stdout",
            "--cov-report=",
            "-q",
            "-rs",
            "-p",
            "no:cacheprovider",
        ],
        cwd=BACKEND,
        env=env_with_venv(),
    )
    text = r.stdout
    summary = re.search(r"(\d+) passed(?:, (\d+) skipped)?(?:, (\d+) failed)?", text)
    if summary is None:
        raise SystemExit(f"could not parse pytest output:\n{text[-2000:]}\n{r.stderr[-2000:]}")
    cov_json = json.loads(text[text.index("{") : text.rindex("}") + 1])
    totals = cov_json["totals"]
    backend = {
        "command": "pytest --cov=triage_desk",
        "passed": int(summary.group(1)),
        "skipped": int(summary.group(2) or 0),
        "failed": int(summary.group(3) or 0),
        "skip_reasons": re.findall(r"SKIPPED \[\d+\] (.*)", text),
        "line_coverage_percent": round(totals["percent_covered"], 2),
        "statements": totals["num_statements"],
        "missing": totals["missing_lines"],
    }
    dashboard: dict[str, Any] = {"command": "npm ci && npx vitest run --coverage"}
    if shutil.which("npm"):
        log("dashboard: npm ci && npx vitest run --coverage")
        ci = run(["npm", "ci", "--no-audit", "--no-fund"], cwd=DASHBOARD)
        if ci.returncode != 0:
            raise SystemExit(f"npm ci failed:\n{ci.stderr[-2000:]}")
        v = run(["npx", "vitest", "run", "--coverage"], cwd=DASHBOARD)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", v.stdout)
        tests = re.search(r"Tests\s+(\d+) passed(?: \| (\d+) failed)?", plain)
        summ = json.loads((DASHBOARD / "coverage" / "coverage-summary.json").read_text())["total"]
        dashboard.update(
            passed=int(tests.group(1)) if tests else None,
            failed=int(tests.group(2) or 0) if tests else None,
            exit_code=v.returncode,
            line_coverage_percent=summ["lines"]["pct"],
            lines=f"{summ['lines']['covered']}/{summ['lines']['total']}",
            statement_coverage_percent=summ["statements"]["pct"],
            branch_coverage_percent=summ["branches"]["pct"],
        )
    else:
        dashboard["skipped"] = "npm not found"
    return {"backend": backend, "dashboard": dashboard}


# ------------------------------------------------------------------ 2-3. clone + semgrep


def step_clone(workdir: Path) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    for app in APPS:
        dest = workdir / app["name"]
        if not dest.exists():
            log(f"clone {app['url']}")
            r = run(["git", "clone", "--quiet", app["url"], str(dest)])
            if r.returncode != 0:
                raise SystemExit(r.stderr)
        r = run(["git", "-C", str(dest), "checkout", "--quiet", "--detach", app["sha"]])
        if r.returncode != 0:
            raise SystemExit(f"{app['name']}: cannot check out {app['sha']}: {r.stderr}")
        head = run(["git", "-C", str(dest), "rev-parse", "HEAD"]).stdout.strip()
        assert head == app["sha"], (head, app["sha"])


def fetch_ruleset(workdir: Path) -> Path:
    """Local snapshot of p/python, used for the timing runs (no network inside a timed run)."""
    dest = workdir / "p-python.yaml"
    if not dest.exists():
        log(f"download {RULESET_URL}")
        with urllib.request.urlopen(RULESET_URL, timeout=60) as resp:
            dest.write_bytes(resp.read())
    return dest


def step_semgrep(workdir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    per_app: dict[str, Any] = {}
    for app in APPS:
        log(f"semgrep scan --config {RULESET} on {app['name']}")
        cmd = [
            "semgrep",
            "scan",
            "--config",
            RULESET,
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            ".",
        ]
        t0 = time.perf_counter()
        r = run(cmd, cwd=workdir / app["name"], env=env_with_venv())
        elapsed = time.perf_counter() - t0
        if r.returncode not in (0, 1):
            raise SystemExit(f"semgrep failed on {app['name']}: {r.stderr[-2000:]}")
        data = json.loads(r.stdout)
        seen: Counter[tuple[str, str, int]] = Counter()
        for res in sorted(
            data["results"],
            key=lambda x: (x["path"], x["start"]["line"], x["start"]["col"], x["check_id"]),
        ):
            path = res["path"].removeprefix("./")
            key = (path, res["check_id"], res["start"]["line"])
            seen[key] += 1
            line = res["start"]["line"]
            findings.append(
                {
                    "id": f"{app['name']}:{path}:{line}:{res['check_id']}:{seen[key]}",
                    "app": app["name"],
                    "path": path,
                    "line": res["start"]["line"],
                    "col": res["start"]["col"],
                    "rule_id": res["check_id"],
                    "severity": res["extra"].get("severity"),
                }
            )
        per_app[app["name"]] = {
            "url": app["url"],
            "sha": app["sha"],
            "command": " ".join(cmd),
            "findings": len(data["results"]),
            "files_scanned": len(data["paths"]["scanned"]),
            "semgrep_errors": len(data["errors"]),
            "wall_seconds_single_run": round(elapsed, 2),
            "scanned_paths": sorted(p.removeprefix("./") for p in data["paths"]["scanned"]),
        }
    return findings, per_app


# ------------------------------------------------------------------ 4. reachability


def step_reach(workdir: Path, findings: list[dict[str, Any]]) -> dict[str, Any]:
    from triage_desk.reachability import reaches

    sources: dict[tuple[str, str], str] = {}
    for f in findings:
        k = (f["app"], f["path"])
        if k not in sources:
            sources[k] = (workdir / f["app"] / f["path"]).read_text("utf-8", errors="replace")

    per_finding_median_us: list[float] = []
    for f in findings:
        src = sources[(f["app"], f["path"])]
        times = []
        res = None
        for _ in range(RUNS):
            t0 = time.perf_counter_ns()
            res = reaches(src, f["line"])
            times.append((time.perf_counter_ns() - t0) / 1000)
        assert res is not None
        f["hint"] = res.label
        f["hint_reason"] = res.reason
        f["hint_variable"] = res.variable
        f["hint_def_line"] = res.def_line
        f["reach_median_us"] = round(statistics.median(times), 1)
        per_finding_median_us.append(statistics.median(times))

    pass_ms = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        for f in findings:
            reaches(sources[(f["app"], f["path"])], f["line"])
        pass_ms.append((time.perf_counter() - t0) * 1000)

    counts = Counter(f["hint"] for f in findings)
    by_app = {
        a["name"]: dict(Counter(f["hint"] for f in findings if f["app"] == a["name"])) for a in APPS
    }
    return {
        "findings": len(findings),
        "labels": {k: counts.get(k, 0) for k in ("tainted", "not_tainted", "unknown")},
        "labels_by_app": by_app,
        "timing": {
            "runs": RUNS,
            "per_finding_us_median_of_medians": round(statistics.median(per_finding_median_us), 1),
            "per_finding_us_p95_of_medians": round(p95(per_finding_median_us), 1),
            "per_finding_us_max_of_medians": round(max(per_finding_median_us), 1),
            "full_pass_ms_median": round(statistics.median(pass_ms), 2),
            "full_pass_ms_runs": [round(x, 2) for x in pass_ms],
            "note": "reaches(source, line) only; file already in memory; includes ast.parse",
        },
    }


# ------------------------------------------------------------------ 5. accuracy


def stratified_sample(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rng = random.Random(SAMPLE_SEED)
    strata: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        strata.setdefault(f["hint"], []).append(f)
    remaining = min(SAMPLE_SIZE, len(findings))
    picked: list[dict[str, Any]] = []
    order = sorted(strata, key=lambda k: len(strata[k]))  # smallest stratum first
    for i, label in enumerate(order):
        quota = min(len(strata[label]), remaining // (len(order) - i))
        picked += rng.sample(sorted(strata[label], key=lambda f: f["id"]), quota)
        remaining -= quota
    return sorted(picked, key=lambda f: f["id"])


LABEL_FIELDS = [
    "id",
    "app",
    "path",
    "line",
    "rule_id",
    "hint",
    "truth_in_function",
    "reachable_via_caller",
    "reason",
]


def step_accuracy(findings: list[dict[str, Any]]) -> dict[str, Any]:
    sample = stratified_sample(findings)
    if not LABELS.exists():
        with LABELS.open("w", newline="") as fh:
            w = csv.DictWriter(fh, LABEL_FIELDS)
            w.writeheader()
            for f in sample:
                w.writerow({k: f.get(k, "") for k in LABEL_FIELDS[:6]})
        raise SystemExit(f"wrote an unlabelled template to {LABELS}; label it and re-run")

    rows = list(csv.DictReader(LABELS.open()))
    by_id = {f["id"]: f for f in findings}
    if sorted(r["id"] for r in rows) != [f["id"] for f in sample]:
        raise SystemExit("labels.csv does not match the stratified sample of this run")
    for r in rows:
        if r["hint"] != by_id[r["id"]]["hint"]:
            raise SystemExit(
                f"hint changed for {r['id']}: csv {r['hint']}, now {by_id[r['id']]['hint']}"
            )
        if r["truth_in_function"] not in ("yes", "no"):
            raise SystemExit(f"unlabelled row {r['id']}")

    def pr(truth_col: str) -> dict[str, Any]:
        tp = sum(r["hint"] == "tainted" and r[truth_col] == "yes" for r in rows)
        fp = sum(r["hint"] == "tainted" and r[truth_col] == "no" for r in rows)
        fn = sum(r["hint"] != "tainted" and r[truth_col] == "yes" for r in rows)
        tn = sum(r["hint"] != "tainted" and r[truth_col] == "no" for r in rows)
        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        }

    # "reachable at all": in-function flow, or a flow that arrives through a caller.
    for r in rows:
        r["truth_any"] = (
            "yes" if "yes" in (r["truth_in_function"], r["reachable_via_caller"]) else "no"
        )
    strata = Counter(r["hint"] for r in rows)
    population = Counter(f["hint"] for f in findings)
    deprio = [r for r in rows if r["hint"] == "not_tainted"]
    return {
        "sample_size": len(rows),
        "population": len(findings),
        "sample_strata": dict(strata),
        "population_strata": dict(population),
        "seed": SAMPLE_SEED,
        "reviewers": 1,
        "tainted_vs_in_function_truth": pr("truth_in_function"),
        "tainted_vs_any_path_truth": pr("truth_any"),
        "deprioritised_share_population": round(population["not_tainted"] / len(findings), 4),
        "deprioritised_in_sample": len(deprio),
        "deprioritised_in_sample_truly_unreachable_in_function": sum(
            r["truth_in_function"] == "no" for r in deprio
        ),
        "deprioritised_in_sample_reachable_via_caller": sum(
            r["reachable_via_caller"] == "yes" for r in deprio
        ),
    }


# ------------------------------------------------------------------ 6. scan job


def step_scan(workdir: Path, findings_meta: dict[str, Any], ruleset: Path) -> dict[str, Any]:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from tests.fakes import FakeGitHub
    from triage_desk.config import Settings
    from triage_desk.jobs import run_scan
    from triage_desk.models import Base
    from triage_desk.scanner import SemgrepCli

    class TimedScanner(SemgrepCli):
        last_s = 0.0

        def scan(self, root, files):  # type: ignore[no-untyped-def]
            t0 = time.perf_counter()
            try:
                return super().scan(root, files)
            finally:
                TimedScanner.last_s = time.perf_counter() - t0

    pool = sorted(f"{a}/{p}" for a, m in findings_meta.items() for p in m["scanned_paths"])
    rng = random.Random(SAMPLE_SEED)
    settings = Settings(webhook_secret="bench", github_token="x", bot_login="bench-bot")
    out: dict[str, Any] = {"ruleset": str(ruleset.name), "file_pool": len(pool), "batches": {}}
    for n in BATCHES:
        batch = sorted(rng.sample(pool, n))
        files = {}
        for name in batch:
            text = (workdir / name).read_text("utf-8", errors="replace")
            patch = f"@@ -0,0 +1,{len(text.splitlines())} @@\n" + "\n".join(
                "+" + ln for ln in text.splitlines()
            )
            files[name] = (text, patch)
        totals, semgrep_s, summaries = [], [], []
        for i in range(RUNS):
            engine = create_engine(
                "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
            )
            Base.metadata.create_all(engine)
            session = sessionmaker(bind=engine, expire_on_commit=False)()
            gh = FakeGitHub(files=dict(files))
            scanner = TimedScanner(str(ruleset))
            t0 = time.perf_counter()
            s = run_scan(session, gh, scanner, settings, "bench/app", 1, f"{i:040x}")
            session.commit()
            totals.append(time.perf_counter() - t0)
            semgrep_s.append(TimedScanner.last_s)
            summaries.append((s.files_scanned, s.findings, s.new_comments, s.error))
            session.close()
            engine.dispose()
        if len(set(summaries)) != 1 or summaries[0][3]:
            raise SystemExit(f"inconsistent scan results for batch {n}: {summaries}")
        fs, nf, nc, _ = summaries[0]
        out["batches"][str(n)] = {
            "files": n,
            "py_lines": sum(len(t.splitlines()) for t, _ in files.values()),
            "files_scanned": fs,
            "findings": nf,
            "review_comments": nc,
            "runs": RUNS,
            "job_seconds_median": round(statistics.median(totals), 3),
            "job_seconds_runs": [round(x, 3) for x in totals],
            "semgrep_seconds_median": round(statistics.median(semgrep_s), 3),
            "non_semgrep_seconds_median": round(
                statistics.median(t - s for t, s in zip(totals, semgrep_s, strict=True)), 4
            ),
            "file_list": batch,
        }
        log(f"scan batch {n}: median {statistics.median(totals):.2f}s")
    return out


# ------------------------------------------------------------------ 7. webhook


def step_webhook() -> dict[str, Any]:
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from tests.fakes import FakeQueue
    from triage_desk.config import Settings
    from triage_desk.main import create_app
    from triage_desk.models import Base
    from triage_desk.webhook_security import sign, verify_signature

    secret = "bench-secret-" + "0" * 51

    def payload(i: int, pad: int = 0) -> bytes:
        return json.dumps(
            {
                "action": "synchronize",
                "repository": {"full_name": "acme/app"},
                "pull_request": {
                    "number": i,
                    "draft": False,
                    "head": {"sha": f"{i:040x}"},
                    "body": "x" * pad,
                },
            }
        ).encode()

    result: dict[str, Any] = {"n": WEBHOOK_N, "percentile": "nearest-rank"}

    # (a) verify_signature() alone, two body sizes.
    for label, pad in (("small", 0), ("25KiB", 25 * 1024)):
        bodies = [payload(i, pad) for i in range(WEBHOOK_N)]
        headers = [sign(secret, b) for b in bodies]
        times, ok = [], 0
        for b, h in zip(bodies, headers, strict=True):
            t0 = time.perf_counter_ns()
            ok += verify_signature(secret, b, h)
            times.append((time.perf_counter_ns() - t0) / 1000)
        result[f"verify_signature_{label}"] = {
            "body_bytes": len(bodies[0]),
            "accepted": ok,
            "median_us": round(statistics.median(times), 2),
            "p95_us": round(p95(times), 2),
        }

    # (b) full POST /webhook in-process (FastAPI TestClient, in-memory SQLite, fake queue).
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    queue = FakeQueue()
    client = TestClient(create_app(Settings(webhook_secret=secret), sessions, queue))

    def post(body: bytes, delivery: str, sig: str) -> tuple[int, str, float]:
        h = {
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery,
            "X-Hub-Signature-256": sig,
            "Content-Type": "application/json",
        }
        t0 = time.perf_counter_ns()
        r = client.post("/webhook", content=body, headers=h)
        dt = (time.perf_counter_ns() - t0) / 1000
        status = r.json().get("status", r.json().get("detail", "")) if r.content else ""
        return r.status_code, status, dt

    bodies = [payload(i) for i in range(WEBHOOK_N)]
    first = [post(b, f"d-{i}", sign(secret, b)) for i, b in enumerate(bodies)]
    replay = [post(b, f"d-{i}", sign(secret, b)) for i, b in enumerate(bodies)]
    forged = [post(b, f"f-{i}", "sha256=" + "0" * 64) for i, b in enumerate(bodies)]
    result["endpoint"] = {
        "what": "POST /webhook via TestClient: HMAC + delivery-id insert + enqueue",
        "first_delivery_accepted": sum(s == "scan-enqueued" for _, s, _ in first),
        "first_median_us": round(statistics.median(t for *_, t in first), 1),
        "first_p95_us": round(p95([t for *_, t in first]), 1),
        "replays_sent": len(replay),
        "replays_rejected": sum(s == "duplicate-delivery-ignored" for _, s, _ in replay),
        "replay_median_us": round(statistics.median(t for *_, t in replay), 1),
        "forged_sent": len(forged),
        "forged_rejected_401": sum(c == 401 for c, _, _ in forged),
        "forged_median_us": round(statistics.median(t for *_, t in forged), 1),
        "forged_p95_us": round(p95([t for *_, t in forged]), 1),
        "scans_enqueued_total": len(queue.scans),
    }
    engine.dispose()
    return result


# ------------------------------------------------------------------ main


def summary() -> None:
    """Print the headline table from bench/results/*.json (no re-measurement)."""

    def load(name: str) -> Any:
        return json.loads((RESULTS / name).read_text())

    env, tests, sem = load("environment.json"), load("tests.json"), load("semgrep.json")
    reach, acc, scan, hook = (
        load("reachability.json"),
        load("accuracy.json"),
        load("scan_job.json"),
        load("webhook.json"),
    )
    b, d = tests["backend"], tests["dashboard"]
    a, n = acc["tainted_vs_in_function_truth"], acc["tainted_vs_any_path_truth"]
    lab = reach["labels"]
    rows = [
        ("backend tests", f"{b['passed']} passed, {b['skipped']} skipped", "pytest"),
        ("backend line coverage", f"{b['line_coverage_percent']}%", f"{b['statements']} stmts"),
        ("dashboard tests", f"{d['passed']} passed", "vitest"),
        ("dashboard line coverage", f"{d['line_coverage_percent']}%", f"{d['lines']} lines"),
        ("semgrep p/python findings", str(sem["total_findings"]), f"{len(sem['apps'])} apps"),
        (
            "hint: tainted / not / unknown",
            f"{lab['tainted']} / {lab['not_tainted']} / {lab['unknown']}",
            f"n={reach['findings']}",
        ),
        (
            "precision of tainted",
            f"{a['tp']}/{a['tp'] + a['fp']}",
            f"n={acc['sample_size']} labelled",
        ),
        ("recall, in-function", f"{a['tp']}/{a['tp'] + a['fn']}", f"n={acc['sample_size']}"),
        ("recall, incl. via caller", f"{n['tp']}/{n['tp'] + n['fn']}", f"n={acc['sample_size']}"),
        (
            "deprioritisable (not_tainted)",
            f"{lab['not_tainted']}/{reach['findings']}",
            "all findings",
        ),
        (
            "reaches() per finding",
            f"{reach['timing']['per_finding_us_median_of_medians'] / 1000:.2f} ms",
            "median, 5 runs",
        ),
    ]
    for k, v in scan["batches"].items():
        rows.append((f"run_scan, {k} files", f"{v['job_seconds_median']:.2f} s", "median of 5"))
    rows += [
        (
            "verify_signature, 186 B",
            f"{hook['verify_signature_small']['median_us']} us",
            f"median, n={hook['n']}",
        ),
        (
            "POST /webhook",
            f"{hook['endpoint']['first_median_us'] / 1000:.2f} ms",
            f"median, n={hook['n']}",
        ),
        (
            "replays rejected",
            f"{hook['endpoint']['replays_rejected']}/{hook['endpoint']['replays_sent']}",
            "same delivery id",
        ),
    ]
    w0, w1 = max(len(r[0]) for r in rows), max(len(r[1]) for r in rows)
    print(
        f"triage-desk benchmark  |  {env['cpu']}  |  Python {env['python']}  |  "
        f"semgrep {env['semgrep_cli']}"
    )
    print("-" * (w0 + w1 + 24))
    for k, v, c in rows:
        print(f"{k:<{w0}}  {v:>{w1}}  {c}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workdir", type=Path, default=Path("/tmp/bench"))
    ap.add_argument("--skip-tests", action="store_true", help="skip pytest / vitest coverage")
    ap.add_argument("--summary", action="store_true", help="only print the saved results")
    args = ap.parse_args()
    if args.summary:
        summary()
        return
    os.environ["PATH"] = env_with_venv()["PATH"]  # SemgrepCli resolves "semgrep" on PATH
    if shutil.which("semgrep") is None:
        raise SystemExit("semgrep not found next to this interpreter or on PATH")

    write("environment.json", environment())
    if not args.skip_tests:
        write("tests.json", step_tests())
    step_clone(args.workdir)
    ruleset = fetch_ruleset(args.workdir)
    digest = hashlib.sha256(ruleset.read_bytes()).hexdigest()
    findings, per_app = step_semgrep(args.workdir)
    reach = step_reach(args.workdir, findings)
    write(
        "semgrep.json",
        {
            "ruleset": RULESET,
            "apps": per_app,
            "total_findings": len(findings),
            "snapshot_sha256": digest,
            "snapshot_matches_published": digest == RULESET_SHA256,
        },
    )
    write("reachability.json", reach)
    write("findings.json", findings)
    write("accuracy.json", step_accuracy(findings))
    write("scan_job.json", step_scan(args.workdir, per_app, ruleset))
    write("webhook.json", step_webhook())
    log("done")
    summary()


if __name__ == "__main__":
    main()
