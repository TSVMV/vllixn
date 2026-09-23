"""Read-only access to the local system.

Every check receives a ``SystemProbe``. The probe resolves paths under a
configurable root (``/`` by default) so the whole checkup can run against a
fixture tree in tests, and it can run a small allow-list of read-only commands
through an injectable runner. It never writes to the system.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CommandResult", "FileInfo", "SubprocessRunner", "SystemProbe"]

# Only these executables may be invoked. Every entry is a read-only query.
ALLOWED_COMMANDS = frozenset(
    {
        "aa-status",
        "apt",
        "apt-get",
        "auditctl",
        "dpkg-query",
        "dnf",
        "firewall-cmd",
        "getenforce",
        "ip",
        "iptables",
        "nft",
        "rpm",
        "ss",
        "sysctl",
        "systemctl",
        "timedatectl",
        "ufw",
        "uname",
        "yum",
    }
)


@dataclass
class CommandResult:
    """Result of a read-only command invocation."""

    args: tuple[str, ...]
    code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.code == 0

    @property
    def missing(self) -> bool:
        return self.code == 127


@dataclass
class FileInfo:
    """A small, portable snapshot of a path's metadata."""

    path: str
    mode: int
    uid: int
    gid: int
    is_dir: bool
    is_symlink: bool
    size: int
    mtime: float = 0.0

    @property
    def perm(self) -> int:
        """Permission bits only, e.g. 0o644."""
        return self.mode & 0o7777

    @property
    def perm_text(self) -> str:
        """Permission bits as a three or four digit octal string."""
        return f"{self.perm:03o}"

    def any_write(self, *, group: bool = True, other: bool = True) -> bool:
        """True when the file is writable by group and/or other."""
        mask = 0
        if group:
            mask |= 0o020
        if other:
            mask |= 0o002
        return bool(self.perm & mask)

    @property
    def other_write(self) -> bool:
        return bool(self.perm & 0o002)

    @property
    def group_write(self) -> bool:
        return bool(self.perm & 0o020)

    @property
    def other_read_owner(self) -> bool:
        return bool(self.perm & 0o004)


class SubprocessRunner:
    """Run read-only commands with a hard timeout; never raise on failure."""

    def run(self, args: Iterable[str], timeout: float = 10.0) -> CommandResult:
        argv = tuple(str(item) for item in args)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(argv, 124, self._as_text(exc.stdout), "命令超时")
        except (OSError, subprocess.SubprocessError) as exc:
            return CommandResult(argv, 127, "", str(exc))
        return CommandResult(argv, proc.returncode, proc.stdout, proc.stderr)

    @staticmethod
    def _as_text(value: bytes | str | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return value


class SystemProbe:
    """Filesystem and command access rooted at ``root`` (default ``/``)."""

    def __init__(
        self,
        root: str | Path = "/",
        *,
        uid: int | None = None,
        runner: SubprocessRunner | None = None,
    ) -> None:
        self.root = Path(root)
        self._uid = os.geteuid() if uid is None else uid
        self.runner = runner or SubprocessRunner()

    @property
    def is_root(self) -> bool:
        """Whether the effective user can read root-only files such as shadow."""
        return self._uid == 0

    def hostname(self) -> str:
        name = self.read_text("/proc/sys/kernel/hostname", "").strip()
        if name:
            return name
        try:
            return os.uname().nodename
        except OSError:
            return "unknown"

    def kernel(self) -> str:
        release = self.read_text("/proc/sys/kernel/osrelease", "").strip()
        return release or "unknown"

    def distro(self) -> str:
        text = self.read_text("/etc/os-release", "")
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return "unknown"

    def path(self, rel: str | Path) -> Path:
        """Resolve ``rel`` under the probe root."""
        return self.root / str(rel).lstrip("/")

    def exists(self, rel: str) -> bool:
        return self.path(rel).exists()

    def is_file(self, rel: str) -> bool:
        return self.path(rel).is_file()

    def is_dir(self, rel: str) -> bool:
        return self.path(rel).is_dir()

    def read_text(self, rel: str, default: str = "") -> str:
        try:
            return self.path(rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return default

    def read_lines(self, rel: str) -> list[str]:
        text = self.read_text(rel, "")
        if not text:
            return []
        return text.splitlines()

    def info(self, rel: str, *, follow: bool = False) -> FileInfo | None:
        """Stat ``rel``; with ``follow=False`` symlinks are not dereferenced."""
        try:
            stat = os.stat(self.path(rel), follow_symlinks=follow)
        except OSError:
            return None
        return FileInfo(
            path=f"/{str(rel).lstrip('/')}",
            mode=stat.st_mode,
            uid=stat.st_uid,
            gid=stat.st_gid,
            is_dir=os.path.isdir(self.path(rel)) if follow else (stat.st_mode & 0o170000) == 0o040000,
            is_symlink=os.path.islink(self.path(rel)),
            size=stat.st_size,
            mtime=stat.st_mtime,
        )

    def list_dir(self, rel: str) -> list[str]:
        try:
            return sorted(entry.name for entry in self.path(rel).iterdir())
        except OSError:
            return []

    def glob(self, rel: str) -> list[str]:
        """Glob under the root, returning paths as absolute-looking strings."""
        base = self.root
        try:
            matches = sorted(base.glob(str(rel).lstrip("/")))
        except (OSError, ValueError):
            return []
        out: list[str] = []
        for match in matches:
            try:
                out.append("/" + str(match.relative_to(base)))
            except ValueError:
                continue
        return out

    def command(self, args: Iterable[str], timeout: float = 10.0) -> CommandResult:
        """Run an allow-listed read-only command."""
        argv = [str(item) for item in args]
        if not argv:
            return CommandResult((), 127, "", "空命令")
        name = os.path.basename(argv[0])
        if name not in ALLOWED_COMMANDS:
            return CommandResult(tuple(argv), 126, "", f"命令不在允许列表：{name}")
        return self.runner.run(argv, timeout)

    def command_text(self, args: Iterable[str], timeout: float = 10.0) -> str:
        result = self.command(args, timeout)
        return result.stdout if result.ok else ""
