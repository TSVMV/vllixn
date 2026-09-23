"""Tests for audit and hardening layer checks."""

from __future__ import annotations

from conftest import make_probe, write

from vllixn.checks import audit
from vllixn.model import Severity, Status
from vllixn.probe import CommandResult

DATECTL_SYNCED = "System clock synchronized: yes\nNTP service: active\n"
DATECTL_UNSYNCED = "System clock synchronized: no\nNTP service: inactive\n"


def test_selinux_enforcing_passes(root):
    probe = make_probe(root, {("getenforce",): CommandResult((), 0, "Enforcing\n")})
    assert audit._mac(probe).status is Status.PASS


def test_selinux_permissive_is_medium(root):
    probe = make_probe(root, {("getenforce",): CommandResult((), 0, "Permissive\n")})
    finding = audit._mac(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_apparmor_enabled_passes(root):
    write(root, "/sys/module/apparmor/parameters/enabled", "Y\n")
    assert audit._mac(make_probe(root)).status is Status.PASS


def test_no_mac_layer_fails_low(root):
    finding = audit._mac(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_auditd_enabled_passes(root):
    probe = make_probe(root, {("auditctl", "-s"): CommandResult((), 0, "enabled 1\npid 100\n")})
    assert audit._auditd(probe).status is Status.PASS


def test_auditd_disabled_fails(root):
    probe = make_probe(root, {("auditctl", "-s"): CommandResult((), 0, "enabled 0\n")})
    finding = audit._auditd(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_auditd_absent_fails_low(root):
    finding = audit._auditd(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_auditd_installed_but_unreadable_skips(root):
    write(root, "/etc/audit/auditd.conf", "log_file = /var/log/audit/audit.log\n")
    finding = audit._auditd(make_probe(root))
    assert finding.status is Status.SKIP


def test_time_synced_passes(root):
    probe = make_probe(root, {("timedatectl",): CommandResult((), 0, DATECTL_SYNCED)})
    assert audit._time_sync(probe).status is Status.PASS


def test_time_unsynced_fails(root):
    probe = make_probe(root, {("timedatectl",): CommandResult((), 0, DATECTL_UNSYNCED)})
    finding = audit._time_sync(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_time_sync_config_only_skips(root):
    write(root, "/etc/chrony.conf", "pool pool.ntp.org iburst\n")
    assert audit._time_sync(make_probe(root)).status is Status.SKIP


def test_persistent_logs_rsyslog_passes(root):
    write(root, "/etc/rsyslog.conf", "*.* /var/log/syslog\n")
    assert audit._persistent_logs(make_probe(root)).status is Status.PASS


def test_persistent_logs_missing_fails(root):
    finding = audit._persistent_logs(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_persistent_logs_journald_dir_passes(root):
    (root / "var" / "log" / "journal").mkdir(parents=True)
    assert audit._persistent_logs(make_probe(root)).status is Status.PASS
