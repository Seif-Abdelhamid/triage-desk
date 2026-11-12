"""Parser for `/triage` comment commands.

Grammar (first non-empty line of the comment only)::

    /triage false-positive [#<finding-id>] <reason>
    /triage accept-risk    [#<finding-id>] <reason>
    /triage fixed          [#<finding-id>] [note]

The finding id is optional when the command is a reply in the bot's review
thread (the thread identifies the finding). The parser is a strict regex, the
reason is length-limited and stripped of control and markdown-active
characters, and nothing in it is ever executed or interpolated into a query.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from .models import FindingStatus

ACTIONS: dict[str, FindingStatus] = {
    "false-positive": FindingStatus.false_positive,
    "accept-risk": FindingStatus.accepted_risk,
    "fixed": FindingStatus.fixed,
}
REASON_REQUIRED = {"false-positive", "accept-risk"}
MAX_REASON = 300

_CMD_RE = re.compile(
    r"^/triage\s+(?P<action>[a-z-]+)(?:\s+#(?P<id>\d{1,9}))?(?:\s+(?P<reason>.*))?$"
)
_UNSAFE = re.compile(r"[`<>\[\]|*_~@#\\]")


class CommandError(ValueError):
    """The comment starts with /triage but is not a valid command."""


@dataclass(frozen=True)
class TriageCommand:
    action: str
    new_status: FindingStatus
    finding_id: int | None
    reason: str | None


def sanitize_reason(raw: str) -> str:
    text = "".join(
        ch for ch in unicodedata.normalize("NFKC", raw) if unicodedata.category(ch)[0] != "C"
    )
    text = _UNSAFE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_REASON]


def parse(body: str) -> TriageCommand | None:
    """Return the command, None if the comment is not a /triage command.

    Raises CommandError for a malformed /triage command so the bot can reply
    with usage instead of silently ignoring it.
    """
    first = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
    if not first.startswith("/triage"):
        return None
    if len(first) > 1000:
        raise CommandError("command too long")
    m = _CMD_RE.match(first)
    if m is None:
        raise CommandError("could not parse command")
    action = m.group("action")
    if action not in ACTIONS:
        raise CommandError(f"unknown action {action!r}")
    reason = sanitize_reason(m.group("reason") or "") or None
    if action in REASON_REQUIRED and not reason:
        raise CommandError(f"/triage {action} needs a reason")
    fid = int(m.group("id")) if m.group("id") else None
    return TriageCommand(action, ACTIONS[action], fid, reason)


USAGE = (
    "Usage: `/triage false-positive <reason>`, `/triage accept-risk <reason>` or "
    "`/triage fixed`, as a reply in a finding's review thread "
    "(or add `#<finding-id>` after the action in a PR comment)."
)
