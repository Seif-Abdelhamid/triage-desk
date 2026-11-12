# ADR 0001: Autoscale scan workers on queue depth plus in-flight tasks

- Status: accepted
- Date: 2026-11-12
- Scope: the `scans` Celery queue and the worker deployment that consumes it

## Context

A pull-request scan is a long, uneven task. The worker fetches the changed
files from GitHub, runs `semgrep scan`, and posts review comments. That takes
seconds for a small PR and minutes for a large one, with most of the time spent
inside Semgrep.

The usual signal for scaling queue consumers is **queue depth**: the length of
the Redis list behind the queue (`LLEN scans`). That is what KEDA's Redis-list
scaler reads by default. For this workload it gives the wrong answer at the
worst time:

1. Three PRs arrive. Depth goes 0 → 3. The autoscaler adds workers.
2. Each worker pulls a task. Depth drops back to **0**, even though all three
   workers are busy running Semgrep for the next several minutes.
3. Once the cooldown ends, a depth-only autoscaler sees an empty queue and
   scales in. Worker pods get SIGTERM while they are mid-scan. With
   `acks_late` the tasks are redelivered, so the work runs again from the start
   on whatever capacity is left. Without `acks_late` the work is lost.

Depth tells you how much work is **waiting**. It says nothing about how much is
**running**. For short tasks the gap doesn't matter. For multi-minute tasks it
does.

Prefetching makes it worse. By default a Celery worker reserves
`concurrency × 4` messages. Those messages are off the Redis list, so they
don't count toward depth, but they aren't running either. They sit in one
worker's memory, and a newly added worker can't take them.

## Decision

1. **Track in-flight tasks explicitly.** Celery's `task_prerun` signal writes
   `task_id → start time` into the Redis hash `triage-desk:inflight`, and
   `task_postrun` deletes it (`triage_desk/metrics.py`, `triage_desk/worker.py`).
   Entries older than the task hard time limit (`TASK_HARD_LIMIT_S`) are
   pruned whenever the metric is read. A worker killed with SIGKILL never runs
   `postrun`, and pruning keeps it from inflating the count forever.
2. **Expose both signals at `/metrics`** in Prometheus text format:
   - `triage_desk_queue_depth`: tasks waiting
   - `triage_desk_inflight_tasks`: tasks executing
   - `triage_desk_desired_workers` = `ceil((depth + inflight) / TARGET_TASKS_PER_WORKER)`
3. **Make "waiting" mean waiting.** Set `worker_prefetch_multiplier = 1`,
   `task_acks_late = True` and `task_reject_on_worker_lost = True`. Each worker
   then holds only the tasks it is running, and a task whose worker dies goes
   back on the queue.
4. **Scale on the sum.** With KEDA, use the Prometheus scaler on
   `triage_desk_queue_depth + triage_desk_inflight_tasks` with
   `threshold = TARGET_TASKS_PER_WORKER`. KEDA then computes the same
   ceiling-divide that `desired_workers` shows. Give the worker pods a
   termination grace period at least as long as the task time limit, so scale-in
   lets a running scan finish.

## Alternatives considered

- **`celery inspect active`**: a broadcast to every worker that has to wait for
  replies. It's slow and gets slower as the fleet grows. It also returns
  nothing for a worker that is too busy to answer, which undercounts exactly
  when load is high.
- **Flower / Celery events**: these work, but they add another always-on
  component and an event stream just to get one gauge.
- **Scale on CPU**: Semgrep is CPU-heavy, but CPU lags the queue. A burst of
  PRs waits a full metrics interval before anything happens, and CPU can't tell
  "busy" apart from "stuck".
- **Depth only, with a long cooldown**: this hides the problem without fixing
  it. The cooldown has to be longer than the slowest scan, which wastes
  capacity after every burst.

## Consequences

- Scale-in waits until running work has drained, not just the queue.
- The in-flight count is approximate for at most `TASK_HARD_LIMIT_S` after a
  worker crash. That's acceptable for a scaling signal, and the count errs
  toward too many workers rather than too few.
- `prefetch_multiplier = 1` adds a little broker round-trip overhead per task.
  That cost is negligible next to a scan that runs for minutes.

## Not claimed

This repository ships the metric, the formula and the worker settings, with
unit tests (`tests/test_metrics.py`). It does **not** include a KEDA manifest
that has been run against a cluster, and it reports no production or load-test
results.
