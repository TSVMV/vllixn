"""Tests for enabled service checks."""

from __future__ import annotations

from conftest import make_probe, write

from vllixn.checks import services
from vllixn.model import Severity, Status
from vllixn.probe import CommandResult

CLEAN_UNITS = "ssh.service enabled enabled\nsystemd-resolved.service enabled enabled\n"


def test_risky_unit_detected(root):
    output = CLEAN_UNITS + "telnet.socket enabled enabled\n"
    probe = make_probe(root, {tuple(services.SYSTEMCTL_ARGS): CommandResult((), 0, output)})
    finding = services._enabled_units(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH
    assert "telnet.socket" in finding.evidence


def test_clean_units_pass(root):
    probe = make_probe(root, {tuple(services.SYSTEMCTL_ARGS): CommandResult((), 0, CLEAN_UNITS)})
    finding = services._enabled_units(probe)
    assert finding.status is Status.PASS
    assert "2 个" in finding.title


def test_systemctl_missing_skips(root):
    finding = services._enabled_units(make_probe(root))
    assert finding.status is Status.SKIP


def test_parse_unit_list_takes_first_column():
    units = services.parse_unit_list("a.service enabled enabled\nb.socket enabled enabled\n")
    assert units == ["a.service", "b.socket"]


def test_executable_rc_local_flagged(root):
    write(root, "/etc/rc.local", "#!/bin/sh\nexit 0\n", mode=0o755)
    finding = services._rc_local(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_non_executable_rc_local_passes(root):
    write(root, "/etc/rc.local", "#!/bin/sh\nexit 0\n", mode=0o644)
    finding = services._rc_local(make_probe(root))
    assert finding.status is Status.PASS


def test_missing_rc_local_passes(root):
    assert services._rc_local(make_probe(root)).status is Status.PASS


def test_module_run_smoke(root):
    probe = make_probe(root, {tuple(services.SYSTEMCTL_ARGS): CommandResult((), 0, CLEAN_UNITS)})
    findings = services.run(probe)
    assert {item.category for item in findings} == {"服务"}


def test_cron_deny_present_fails(root):
    write(root, "/etc/cron.deny", "guest\n")
    finding = services._cron_access(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_cron_allow_only_passes(root):
    write(root, "/etc/cron.allow", "root\n")
    finding = services._cron_access(make_probe(root))
    assert finding.status is Status.PASS
