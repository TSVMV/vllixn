"""Tests for filesystem permission checks."""

from __future__ import annotations

import os

from conftest import make_probe, write

from vllixn.checks import permissions
from vllixn.model import Severity, Status


def test_world_writable_system_dir(root):
    os.chmod(root / "etc", 0o777)
    finding = permissions._system_dirs(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.CRITICAL
    assert "/etc" in finding.evidence


def test_readable_shadow_flagged(root):
    write(root, "/etc/shadow", "root:$6$x:1:0:99:7:::\n", mode=0o644)
    finding = permissions._sensitive_files(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH
    assert "/etc/shadow" in finding.evidence


def test_sane_sensitive_files_pass(root):
    write(root, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", mode=0o644)
    write(root, "/etc/shadow", "root:$6$x:1:0:99:7:::\n", mode=0o640)
    write(root, "/etc/sudoers", "root ALL=(ALL:ALL) ALL\n", mode=0o440)
    finding = permissions._sensitive_files(make_probe(root))
    assert finding.status is Status.PASS


def test_world_writable_home(root):
    (root / "home" / "alice").mkdir(parents=True)
    os.chmod(root / "home" / "alice", 0o777)
    finding = permissions._home_dirs(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_risky_suid_flagged(root):
    (root / "usr" / "bin").mkdir(parents=True)
    target = root / "usr" / "bin" / "python3"
    target.write_text("#!/bin/sh\n")
    os.chmod(target, 0o4755)
    finding = permissions._suid(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH
    assert "python3" in finding.evidence


def test_benign_suid_only_passes(root):
    (root / "usr" / "bin").mkdir(parents=True)
    target = root / "usr" / "bin" / "passwd"
    target.write_text("#!/bin/sh\n")
    os.chmod(target, 0o4755)
    finding = permissions._suid(make_probe(root))
    assert finding.status is Status.PASS
