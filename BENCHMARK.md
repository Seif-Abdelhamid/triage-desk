# Benchmark

Every number on this page comes from one run of

```bash
cd projects/triage-desk
uv venv --python 3.12 /tmp/td-venv # or: python3.12 -m venv /tmp/td-venv
VIRTUAL_ENV=/tmp/td-venv uv pip install -e "backend[dev]" semgrep coverage pytest-cov
/tmp/td-venv/bin/python bench/run_benchmark.py
```

The script clones the apps at the pinned commits into `/tmp/bench`, runs every
step and writes the raw output to [`bench/results/`](bench/results). The
hand labels are in [`bench/labels.csv`](bench/labels.csv). Nothing on this
page is estimated or rounded up. Percentages are rounded to one decimal place
from the raw JSON, and each one gives its sample size.

## Machine and versions

|                                |                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------ |
| CPU                            | Apple M2, 8 cores, 8 GiB RAM                                                         |
| OS                             | macOS 26.4 (arm64)                                                                   |
| Python                         | 3.12.13                                                                              |
| Semgrep CLI                    | 1.185.0                                                                              |
| Ruleset                        | `p/python` from the Semgrep registry (151 rules; snapshot sha256 `de5bc79d…62e23f5`) |
| Node                           | v22.22.2, vitest 5.1.0, @vitest/coverage-v8 5.1.0                                    |
| pytest / pytest-cov / coverage | 9.2.0 / 7.1.0 / 7.17.3                                                               |
| SQLAlchemy / FastAPI / httpx   | 2.1.8 / 0.141.1 / 0.28.1                                                             |

Full details: [`bench/results/environment.json`](bench/results/environment.json).

## 1. Tests and coverage

| Suite     | Command                               | Result                          | Coverage                                                             |
| --------- | ------------------------------------- | ------------------------------- | -------------------------------------------------------------------- |
| backend   | `pytest --cov=triage_desk`            | 129 passed, 2 skipped, 0 failed | **93.51 % of lines** (1,066 of 1,140 statements)                     |
| dashboard | `npm ci && npx vitest run --coverage` | 18 passed, 0 failed             | 98.18 % of lines (54/55), 92.95 % of statements, 92.85 % of branches |

The two skipped backend tests need external services: the PostgreSQL
append-only trigger test (`TEST_POSTGRES_URL`) and the docker-compose E2E test
(`TRIAGE_DESK_E2E=1`). Dashboard coverage counts every file under `src/`. The
one uncovered line is `main.tsx`, the React mount call.

## 2. Reachability hint on intentionally vulnerable apps

### Apps

| App                                                                       | Commit                                     | Python files scanned by Semgrep | Findings (`p/python`) |
| ------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------- | --------------------- |
| [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat)       | `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` | 116                             | 59                    |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | `b6a4f97afd466e83e1f60781494252dec1c37039` | 2                               | 5                     |
| [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa)                       | `4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756` | 21                              | 2                     |
| **Total**                                                                 |                                            | 139                             | **66**                |

The command was `semgrep scan --config p/python --json --metrics=off` against
the live registry, with 0 Semgrep errors. The script also downloads a snapshot
of `p/python` for the timing runs. That snapshot gave the same 59 / 5 / 2
findings.

### Labels from the hint (all 66 findings)

`reaches(source, line)` from `triage_desk.reachability` was run on every
finding, the same way `tests/test_reachability.py` calls it.

| Label                                           | pygoat | Vulnerable-Flask-App | dvpwa | Total (n = 66) |
| ----------------------------------------------- | ------ | -------------------- | ----- | -------------- |
| `tainted`                                       | 16     | 5                    | 0     | 21 (31.8 %)    |
| `not_tainted`                                   | 43     | 0                    | 2     | 45 (68.2 %)    |
| `unknown` (unsupported construct / parse error) | 0      | 0                    | 0     | 0              |

### Accuracy against hand labels

**Sample.** 40 of the 66 findings, stratified by hint label (20 `tainted`,
20 `not_tainted`), drawn with `random.Random(0)`. The script rebuilds the
same sample and refuses to score it if `labels.csv` doesn't match.

**Ground truth.** For each finding I read the enclosing function at the
pinned commit and answered one question: does attacker-controlled request
input really reach the flagged line inside this function? That is
`truth_in_function`. I also recorded whether request input reaches the line
through a caller (`reachable_via_caller`), because a reviewer who
deprioritises a finding cares about that case too.

| Metric (n = 40 labelled findings) | In-function truth | Any-path truth (in-function or via a caller) |
| --------------------------------- | ----------------- | -------------------------------------------- |
| TP / FP / FN / TN                 | 20 / 0 / 0 / 20   | 20 / 0 / 3 / 17                              |
| Precision of `tainted`            | **100 % (20/20)** | 100 % (20/20)                                |
| Recall of `tainted`               | 100 % (20/20)     | **87.0 % (20/23)**                           |

**Deprioritising.** The hint labels 45 of 66 findings (68.2 %) `not_tainted`,
so a reviewer could move them down the queue. In the labelled sample, all 20
`not_tainted` findings were truly unreachable inside their function (20/20).
But 3 of those 20 (15 %) _are_ reachable from request input through a caller:
`dvpwa sqli/dao/user.py:41` (two rules on one line) and
`pygoat crypto_failure_lab/app.py:25`. This is the intraprocedural limit the
README already documents.

What these numbers mean:

- 17 of the 20 sampled `not_tainted` findings, and most of the 45 overall, are
  module-level `app.run(host="0.0.0.0", debug=True)` lines. For those, "no
  request flow" is trivially right. This makes the deprioritisation share look
  better than it would on ordinary code.
- 5 of the 20 `tainted` findings are lines where Semgrep reports the _source_
  (`x = request.form.get(...)`) and not the sink. "Tainted" is trivially true
  there.
- For some rules, a true flow doesn't matter to the risk. One example is
  `jwt-python-hardcoded-secret` in `sec_misconfig/app.py:100`: request data
  does reach the `jwt.encode` call, but the finding is about the literal key.
  It is counted as a true positive because it meets the stated definition.
- Recall is measured on the sample, which over-represents `tainted` (20 of 21)
  relative to `not_tainted` (20 of 45). It is not a population estimate.

## 3. Performance

### Scan job end to end

`triage_desk.jobs.run_scan` was run with `tests.fakes.FakeGitHub` (no network),
a fresh in-memory SQLite database per run, and the real `SemgrepCli` with the
local `p/python` snapshot. Each batch is a seeded random sample of the 139
scanned Python files. Every file is presented as fully added, so every
finding's line is commentable. The table reports the median of 5 runs.

| Changed files | Python lines | Findings | Review comments | Job, median of 5 | of which Semgrep | everything else |
| ------------- | ------------ | -------- | --------------- | ---------------- | ---------------- | --------------- |
| 10            | 438          | 3        | 3               | **4.04 s**       | 4.02 s           | 0.020 s         |
| 25            | 1,369        | 9        | 9               | **4.05 s**       | 4.02 s           | 0.037 s         |
| 50            | 3,301        | 21       | 21              | **4.15 s**       | 4.07 s           | 0.071 s         |

Semgrep process start-up and rule loading dominate the job. Fetching files,
fingerprinting, the reachability hint, the DB upserts and the comment calls
take 20 to 71 ms combined. Real GitHub API latency is not included, because
GitHub is faked.

### Reachability pass alone

The table times `reaches(source, line)` on all 66 findings, with the file
already in memory. The time includes `ast.parse` of the whole file.

| Metric (n = 66 findings, 5 runs each)      | Value    |
| ------------------------------------------ | -------- |
| Per finding, median of per-finding medians | 1.24 ms  |
| Per finding, p95 of per-finding medians    | 3.76 ms  |
| Per finding, max of per-finding medians    | 4.22 ms  |
| All 66 findings, median of 5 passes        | 103.6 ms |

## 4. Webhook verification and replay protection

Each test sent 10,000 requests. Percentiles use the nearest-rank method.

| Path                                                                  | Body     | Median   | p95      | Outcome                                    |
| --------------------------------------------------------------------- | -------- | -------- | -------- | ------------------------------------------ |
| `verify_signature()` alone                                            | 186 B    | 2.88 µs  | 3.00 µs  | 10,000 / 10,000 accepted                   |
| `verify_signature()` alone                                            | 25,786 B | 20.54 µs | 26.79 µs | 10,000 / 10,000 accepted                   |
| `POST /webhook`, first delivery (HMAC + delivery-ID insert + enqueue) | 186 B    | 1.61 ms  | 1.87 ms  | 10,000 / 10,000 enqueued                   |
| `POST /webhook`, **replayed** delivery ID with a valid signature      | 186 B    | 1.70 ms  | n/a      | **10,000 / 10,000 rejected** as duplicates |
| `POST /webhook`, forged signature                                     | 186 B    | 1.29 ms  | 1.49 ms  | 10,000 / 10,000 rejected with 401          |

After all 30,000 requests the queue held exactly 10,000 scans, one per
original delivery. The endpoint numbers are in-process (FastAPI `TestClient`,
in-memory SQLite). They don't include a real network hop, TLS, uvicorn or
PostgreSQL.

## Limits

- **Small labelled sample.** The labelled sample has 40 findings from 3 apps,
  and 59 of the 66 findings come from one app (pygoat). The 100 % precision
  and recall figures are 20/20 counts and could change with a few more
  findings.
- **One reviewer.** I labelled every finding myself, so there is no
  inter-rater agreement. Each label has a one-line reason in `labels.csv` so
  anyone can check it.
- **Intraprocedural only.** The ground truth was defined per function, to
  match what the hint claims. Across call boundaries, recall drops to
  20/23 (87.0 %).
- **Intentionally vulnerable apps.** These apps have short handlers that read
  `request` directly, plus many trivial `app.run(debug=True)` findings. That
  is close to a best case for a name-based, intraprocedural analysis, so the
  results may not generalise to production code. Production code has helpers,
  services, ORM layers and aliased request objects.
- **No `unknown` labels occurred.** The `unknown` path (`match` statements,
  syntax errors) is covered by unit tests only, not by this benchmark.
- **Ruleset drift.** `p/python` changes over time. The script records the
  snapshot hash and reports whether it matches the one used here. The live
  registry scan may produce different findings later, and `labels.csv` will
  then stop matching. The script says so and exits; it doesn't score a
  mismatched sample.
- **Timing.** The timings come from one laptop with other software running
  and the CPU in its default power mode. They show the order of magnitude,
  not a server SLA.
