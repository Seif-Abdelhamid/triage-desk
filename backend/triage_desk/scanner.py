"""Run the Semgrep OSS CLI on a directory of fetched PR files."""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol


class ScanError(RuntimeError):
    pass


@dataclass(frozen=True)
class RawFinding:
    rule_id: str
    path: str  # repo-relative, posix
    line: int
    severity: str
    message: str


class Scanner(Protocol):
    def scan(self, root: Path, files: list[str]) -> list[RawFinding]: ...


def safe_relpath(name: str) -> PurePosixPath:
    """Validate a PR file name before it touches the filesystem.

    Rejects absolute paths, ``..`` segments, empty segments, backslashes and
    NUL / control characters (a PR author controls these names).
    """
    if not name or len(name) > 1000 or "\\" in name or any(ord(c) < 32 for c in name):
        raise ScanError(f"unsafe path: {name!r}")
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        raise ScanError(f"unsafe path: {name!r}")
    return p


def parse_semgrep_json(raw: str) -> list[RawFinding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ScanError("semgrep did not return JSON") from exc
    out: list[RawFinding] = []
    for r in data.get("results", []):
        path = str(r["path"])
        path = path[2:] if path.startswith("./") else path
        extra = r.get("extra", {})
        out.append(
            RawFinding(
                rule_id=str(r["check_id"]),
                path=path,
                line=int(r["start"]["line"]),
                severity=str(extra.get("severity", "INFO")),
                message=str(extra.get("message", ""))[:2000],
            )
        )
    return out


class SemgrepCli:
    def __init__(self, config: str, timeout_s: int = 300, binary: str = "semgrep") -> None:
        self.config = config
        self.timeout_s = timeout_s
        self.binary = shutil.which(binary) or binary

    def argv(self, files: list[str]) -> list[str]:
        return [
            self.binary,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            self.config,
            "--timeout",
            "30",
            # "./" prefix: a file named "--config=evil" cannot become an option.
            *[f"./{safe_relpath(f)}" for f in files],
        ]

    def scan(self, root: Path, files: list[str]) -> list[RawFinding]:
        if not files:
            return []
        try:
            # Fixed argv list, shell=False, paths validated by safe_relpath().
            # nosemgrep  (registry audit rule for any non-literal subprocess call)
            proc = subprocess.run(  # noqa: S603  # nosec B603
                self.argv(files),
                cwd=root,
                capture_output=True,
                text=True,
                timeout=self.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("semgrep timed out") from exc
        if proc.returncode not in (0, 1):
            raise ScanError(f"semgrep exited {proc.returncode}: {proc.stderr[-500:]}")
        return parse_semgrep_json(proc.stdout)
