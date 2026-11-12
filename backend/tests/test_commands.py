import pytest

from triage_desk.commands import MAX_REASON, CommandError, parse, sanitize_reason
from triage_desk.models import FindingStatus


def test_not_a_command() -> None:
    assert parse("thanks, LGTM") is None
    assert parse("") is None


def test_false_positive_with_reason() -> None:
    cmd = parse("/triage false-positive only reachable from tests")
    assert cmd is not None
    assert cmd.new_status == FindingStatus.false_positive
    assert cmd.reason == "only reachable from tests"
    assert cmd.finding_id is None


def test_explicit_finding_id() -> None:
    cmd = parse("/triage accept-risk #42 internal tool, tracked in SEC-1")
    assert cmd is not None and cmd.finding_id == 42
    assert cmd.new_status == FindingStatus.accepted_risk


def test_fixed_needs_no_reason() -> None:
    cmd = parse("  \n/triage fixed\nmore text ignored")
    assert cmd is not None and cmd.new_status == FindingStatus.fixed and cmd.reason is None


@pytest.mark.parametrize(
    "body",
    [
        "/triage false-positive",
        "/triage accept-risk   ",
        "/triage delete-all",
        "/triage",
        "/triageFixed",
    ],
)
def test_invalid_commands(body: str) -> None:
    with pytest.raises(CommandError):
        parse(body)


def test_reason_is_sanitized() -> None:
    raw = "ok <img src=x onerror=alert(1)> `rm -rf` @everyone [link](http://e) \x00\x1b[31m"
    cleaned = sanitize_reason(raw)
    for ch in "<>`@[]\x00\x1b":
        assert ch not in cleaned


def test_reason_is_length_limited() -> None:
    cmd = parse("/triage false-positive " + "a" * 900)
    assert cmd is not None and cmd.reason is not None and len(cmd.reason) == MAX_REASON


def test_overlong_command_rejected() -> None:
    with pytest.raises(CommandError):
        parse("/triage false-positive " + "a" * 2000)


def test_only_first_line_is_parsed() -> None:
    # A second /triage line cannot smuggle a second action in.
    cmd = parse("/triage fixed\n/triage false-positive sneaky")
    assert cmd is not None and cmd.new_status == FindingStatus.fixed
