"""Which new-file line numbers a unified-diff patch touches.

GitHub only accepts review comments on lines that are part of the diff, so
findings outside these lines are summarised instead of commented inline.
"""

from __future__ import annotations

import re

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def commentable_lines(patch: str | None) -> set[int]:
    lines: set[int] = set()
    if not patch:
        return lines
    new_line = 0
    for raw in patch.splitlines():
        m = _HUNK.match(raw)
        if m:
            new_line = int(m.group(1))
            continue
        if new_line == 0 or raw.startswith("\\"):
            continue
        if raw.startswith("-"):
            continue
        lines.add(new_line)  # added ("+") and context (" ") lines are both commentable
        new_line += 1
    return lines
