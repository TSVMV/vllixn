"""Shared test fixtures: a fixture filesystem root and a scriptable runner."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vllixn.probe import CommandResult, SubprocessRunner, SystemProbe


class ScriptedRunner(SubprocessRunner):
    """Replay canned command results keyed by argv; unknown commands exit 127."""

    def __init__(self, results: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, ...]] = []

    def run(self, args, timeout: float = 10.0) -> CommandResult:
        argv = tuple(str(item) for item in args)
        self.calls.append(argv)
        canned = self.results.get(argv)
        if canned is not None:
            return canned
        return CommandResult(argv, 127, "", f"no such command: {argv[0]}")


def make_probe(root: Path, results=None, uid: int = 0) -> SystemProbe:
    return SystemProbe(root, uid=uid, runner=ScriptedRunner(results))


def write(
    root: Path,
    rel: str,
    content: str,
    *,
    mode: int | None = None,
    mtime: float | None = None,
) -> Path:
    path = root / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "etc").mkdir()
    (tmp_path / "proc" / "sys").mkdir(parents=True)
    (tmp_path / "var" / "log").mkdir(parents=True)
    return tmp_path
