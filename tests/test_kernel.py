"""Tests for kernel parameter checks."""

from __future__ import annotations

from conftest import make_probe, write

from vllixn.checks import kernel
from vllixn.model import Severity, Status


def _proc(root, rel: str, value: str):
    write(root, f"/proc/sys/{rel}", value + "\n")


def test_net_hardening_bad_value_fails(root):
    _proc(root, "net/ipv4/conf/all/accept_redirects", "1")
    finding = kernel._group(
        make_probe(root),
        "kernel.net_hardening",
        Severity.LOW,
        "网络加固参数未收紧",
        "网络加固参数正常",
        "d",
        "a",
        kernel.NET_HARDENING,
    )
    assert finding.status is Status.FAIL
    assert "accept_redirects" in finding.evidence


def test_net_hardening_all_unreadable_skips(root):
    finding = kernel._group(
        make_probe(root),
        "kernel.net_hardening",
        Severity.LOW,
        "网络加固参数未收紧",
        "网络加固参数正常",
        "d",
        "a",
        kernel.NET_HARDENING,
    )
    assert finding.status is Status.SKIP


def test_net_hardening_clean_passes(root):
    _proc(root, "net/ipv4/conf/all/accept_redirects", "0")
    _proc(root, "net/ipv4/conf/default/accept_redirects", "0")
    _proc(root, "net/ipv4/conf/all/send_redirects", "0")
    _proc(root, "net/ipv4/conf/all/accept_source_route", "0")
    _proc(root, "net/ipv4/conf/all/rp_filter", "1")
    _proc(root, "net/ipv4/icmp_echo_ignore_broadcasts", "1")
    finding = kernel._group(
        make_probe(root),
        "kernel.net_hardening",
        Severity.LOW,
        "网络加固参数未收紧",
        "网络加固参数正常",
        "d",
        "a",
        kernel.NET_HARDENING,
    )
    assert finding.status is Status.PASS


def test_aslr_off_is_high(root):
    _proc(root, "kernel/randomize_va_space", "0")
    finding = kernel._aslr(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH


def test_aslr_partial_is_low(root):
    _proc(root, "kernel/randomize_va_space", "1")
    assert kernel._aslr(make_probe(root)).severity is Severity.LOW


def test_aslr_full_passes(root):
    _proc(root, "kernel/randomize_va_space", "2")
    assert kernel._aslr(make_probe(root)).status is Status.PASS


def test_run_all_groups_smoke(root):
    _proc(root, "kernel/randomize_va_space", "2")
    findings = kernel.run(make_probe(root))
    assert [item.id for item in findings] == [
        "kernel.net_hardening",
        "kernel.info_leak",
        "kernel.aslr",
        "kernel.fs_protect",
    ]


def test_tcp_syncookies_disabled_fails(root):
    _proc(root, "net/ipv4/tcp_syncookies", "0")
    finding = kernel._group(
        make_probe(root),
        "kernel.net_hardening",
        Severity.LOW,
        "网络加固参数未收紧",
        "网络加固参数正常",
        "d",
        "a",
        kernel.NET_HARDENING,
    )
    assert finding.status is Status.FAIL
    assert "tcp_syncookies" in finding.evidence
