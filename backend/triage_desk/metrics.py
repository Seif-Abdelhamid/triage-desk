"""Autoscaling signals: queue depth AND in-flight tasks.

Queue depth alone (LLEN of the broker list) drops to zero the moment workers
pull tasks, even though those workers are still busy for minutes running
Semgrep. An autoscaler watching only depth would scale in while every worker
is mid-scan. In-flight count is tracked explicitly: Celery's
``task_prerun`` / ``task_postrun`` signals add/remove the task id in a Redis
hash (value = start time). Entries older than the task hard time limit are
pruned, so a worker that dies without running postrun cannot leave a stale
count forever. See docs/adr/0001-inflight-autoscaling-signal.md.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any

INFLIGHT_KEY = "triage-desk:inflight"


@dataclass(frozen=True)
class QueueStats:
    queue: str
    depth: int
    inflight: int
    target_per_worker: int

    @property
    def desired_workers(self) -> int:
        """KEDA-style target: ceil((waiting + running) / target per worker)."""
        return math.ceil((self.depth + self.inflight) / max(1, self.target_per_worker))


def mark_started(r: Any, task_id: str, now: float | None = None) -> None:
    r.hset(INFLIGHT_KEY, task_id, str(now if now is not None else time.time()))


def mark_finished(r: Any, task_id: str) -> None:
    r.hdel(INFLIGHT_KEY, task_id)


def inflight_count(r: Any, stale_after_s: float, now: float | None = None) -> int:
    now = now if now is not None else time.time()
    stale = [k for k, v in r.hgetall(INFLIGHT_KEY).items() if now - float(v) > stale_after_s]
    if stale:
        r.hdel(INFLIGHT_KEY, *stale)
    return int(r.hlen(INFLIGHT_KEY))


def queue_depth(r: Any, queue: str) -> int:
    # Celery's Redis transport stores each queue as a list named after it.
    return int(r.llen(queue))


def collect(r: Any, queue: str, stale_after_s: float, target_per_worker: int) -> QueueStats:
    return QueueStats(
        queue, queue_depth(r, queue), inflight_count(r, stale_after_s), target_per_worker
    )


def prometheus_text(s: QueueStats) -> str:
    q = s.queue.replace("\\", "").replace('"', "")
    return (
        "# HELP triage_desk_queue_depth Tasks waiting in the broker queue.\n"
        "# TYPE triage_desk_queue_depth gauge\n"
        f'triage_desk_queue_depth{{queue="{q}"}} {s.depth}\n'
        "# HELP triage_desk_inflight_tasks Tasks currently executing on a worker.\n"
        "# TYPE triage_desk_inflight_tasks gauge\n"
        f'triage_desk_inflight_tasks{{queue="{q}"}} {s.inflight}\n'
        "# HELP triage_desk_desired_workers ceil((depth + inflight) / target per worker).\n"
        "# TYPE triage_desk_desired_workers gauge\n"
        f'triage_desk_desired_workers{{queue="{q}"}} {s.desired_workers}\n'
    )
