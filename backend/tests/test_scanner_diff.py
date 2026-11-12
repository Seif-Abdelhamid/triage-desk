from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from triage_desk.diff import commentable_lines
from triage_desk.scanner import ScanError, SemgrepCli, parse_semgrep_json, safe_relpath


def test_commentable_lines_added_and_context() -> None:
    patch = "@@ -1,3 +1,4 @@\n a\n-b\n+c\n+d\n e\n@@ -20,1 +21,1 @@\n-x\n+y"
    assert commentable_lines(patch) == {1, 2, 3, 4, 21}


def test_commentable_lines_none() -> None:
    assert commentable_lines(None) == set()
    assert commentable_lines("@@ -1 +1 @@\n-a\n+b\n\\ No newline at end of file") == {1}


@pytest.mark.parametrize(
    "bad", ["/etc/passwd", "../x.py", "a/../../x", "a//b", "a\\b", "x\x00.py", "", "./a.py"]
)
def test_safe_relpath_rejects(bad: str) -> None:
    with pytest.raises(ScanError):
        safe_relpath(bad)


def test_safe_relpath_accepts_normal() -> None:
    assert str(safe_relpath("src/pkg/mod.py")) == "src/pkg/mod.py"


def test_argv_has_no_shell_and_prefixes_paths() -> None:
    argv = SemgrepCli("p/python").argv(["--config=evil.yml", "a.py"])
    assert argv[-2:] == ["./--config=evil.yml", "./a.py"]
    assert "--metrics=off" in argv
    assert argv[argv.index("--config") + 1] == "p/python"


def test_parse_semgrep_json() -> None:
    raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "r1",
                    "path": "./a.py",
                    "start": {"line": 3, "col": 1},
                    "extra": {"severity": "WARNING", "message": "m", "lines": "requires login"},
                }
            ],
            "errors": [],
        }
    )
    [f] = parse_semgrep_json(raw)
    assert (f.rule_id, f.path, f.line, f.severity) == ("r1", "a.py", 3, "WARNING")


def test_parse_semgrep_garbage() -> None:
    with pytest.raises(ScanError):
        parse_semgrep_json("not json")


RULE = """
rules:
  - id: shell-true
    languages: [python]
    severity: ERROR
    message: subprocess with shell=True
    pattern: subprocess.run(..., shell=True)
"""


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep CLI not installed")
def test_real_semgrep_with_local_rule(tmp_path: Path) -> None:
    """Runs the real CLI with a local rule file (no registry/network)."""
    rules = tmp_path / "rules.yml"
    rules.write_text(RULE)
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg" / "a.py").write_text("import subprocess\nsubprocess.run('ls', shell=True)\n")
    found = SemgrepCli(str(rules), timeout_s=120).scan(src, ["pkg/a.py"])
    assert [(f.rule_id.split(".")[-1], f.path, f.line) for f in found] == [
        ("shell-true", "pkg/a.py", 2)
    ]
