"""Tests for patch freshness checks."""

from __future__ import annotations

import time

from conftest import make_probe, write

from vllixn.checks import patches
from vllixn.model import Severity, Status


def test_stale_apt_history_fails(root):
    write(root, "/var/lib/dpkg/status", "Package: base\n")
    old = time.time() - 100 * 86400
    write(root, "/var/log/apt/history.log", "Start-Date: old\n", mtime=old)
    finding = patches._update_age(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_recent_update_passes(root):
    write(root, "/var/lib/dpkg/status", "Package: base\n")
    write(root, "/var/log/apt/history.log", "Start-Date: now\n", mtime=time.time())
    finding = patches._update_age(make_probe(root))
    assert finding.status is Status.PASS


def test_marker_without_logs_skips(root):
    write(root, "/var/lib/dpkg/status", "Package: base\n")
    finding = patches._update_age(make_probe(root))
    assert finding.status is Status.SKIP


def test_no_package_manager_skips(root):
    finding = patches._update_age(make_probe(root))
    assert finding.status is Status.SKIP


def test_dnf_log_picked_up(root):
    write(root, "/var/lib/rpm", "")
    old = time.time() - 90 * 86400
    write(root, "/var/log/dnf.log", "2026-06-01 upgrade\n", mtime=old)
    finding = patches._update_age(make_probe(root))
    assert finding.status is Status.FAIL
    assert "rpm/dnf" in finding.detail


def test_uses_newest_log_across_families(root):
    write(root, "/var/lib/dpkg/status", "Package: base\n")
    write(root, "/var/lib/rpm", "")
    fresh = time.time()
    stale = time.time() - 120 * 86400
    write(root, "/var/log/apt/history.log", "fresh\n", mtime=fresh)
    write(root, "/var/log/dnf.log", "stale\n", mtime=stale)
    finding = patches._update_age(make_probe(root))
    assert finding.status is Status.PASS
    assert "dpkg/apt" in finding.detail
