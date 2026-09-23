"""Tests for boot loader, module blacklist and core dump checks."""

from __future__ import annotations

from conftest import make_probe, write

from vllixn.checks import boot
from vllixn.model import Severity, Status


def test_grub_world_writable_is_high(root):
    write(root, "/boot/grub/grub.cfg", "set default=0\n", mode=0o666)
    finding = boot._grub_perms(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH
    assert "grub.cfg" in finding.evidence


def test_grub_clean_passes(root):
    write(root, "/boot/grub/grub.cfg", "set default=0\n", mode=0o600)
    assert boot._grub_perms(make_probe(root)).status is Status.PASS


def test_grub_missing_skips(root):
    assert boot._grub_perms(make_probe(root)).status is Status.SKIP


def test_module_blacklist_empty_fails_low(root):
    write(root, "/etc/modprobe.d/dummy.conf", "# nothing\n")
    finding = boot._module_blacklist(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_module_blacklist_full_passes(root):
    lines = "\n".join(f"blacklist {name}" for name in boot.RISKY_MODULES)
    write(root, "/etc/modprobe.d/cis.conf", lines + "\n")
    assert boot._module_blacklist(make_probe(root)).status is Status.PASS


def test_core_dump_limits_conf_passes(root):
    write(root, "/etc/security/limits.conf", "* hard core 0\n")
    assert boot._core_dump(make_probe(root)).status is Status.PASS


def test_core_dump_systemd_config_passes(root):
    write(root, "/etc/systemd/coredump.conf", "[Coredump]\nStorage=none\n")
    assert boot._core_dump(make_probe(root)).status is Status.PASS


def test_core_dump_missing_fails(root):
    finding = boot._core_dump(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_module_smoke(root):
    findings = boot.run(make_probe(root))
    assert {item.category for item in findings} == {"启动"}
