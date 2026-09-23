"""Tests for network exposure checks."""

from __future__ import annotations

from conftest import make_probe

from vllixn.checks import network
from vllixn.model import Severity, Status
from vllixn.probe import CommandResult

SS_OUTPUT = "\n".join(
    [
        "tcp   LISTEN 0 128   0.0.0.0:22       0.0.0.0:*   users:((\"sshd\",pid=1))",
        "tcp   LISTEN 0 128   [::]:22          [::]:*      users:((\"sshd\",pid=1))",
        "tcp   LISTEN 0 5     127.0.0.1:631    0.0.0.0:*   users:((\"cupsd\",pid=2))",
        "udp   UNCONN 0 0     127.0.0.53:53    0.0.0.0:*",
    ]
)


def test_parse_ss_basic():
    entries = network.parse_ss(SS_OUTPUT)
    assert entries is not None
    assert ("tcp", "0.0.0.0:22") in entries
    assert ("udp", "127.0.0.53:53") in entries


def test_parse_ss_empty_returns_none():
    assert network.parse_ss("") is None


def test_normal_listeners_pass(root):
    probe = make_probe(root, {("ss", "-tulnpH"): CommandResult(("ss",), 0, SS_OUTPUT)})
    finding = network._listening(probe)
    assert finding.status is Status.PASS
    assert "22" in finding.detail


def test_telnet_listener_is_high(root):
    probe = make_probe(
        root,
        {("ss", "-tulnpH"): CommandResult(("ss",), 0, "tcp LISTEN 0 0 0.0.0.0:23 0.0.0.0:*")},
    )
    finding = network._listening(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH
    assert "Telnet" in finding.detail


def test_redis_bound_everywhere_is_medium(root):
    probe = make_probe(
        root,
        {("ss", "-tulnpH"): CommandResult(("ss",), 0, "tcp LISTEN 0 0 0.0.0.0:6379 0.0.0.0:*")},
    )
    finding = network._listening(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_ss_missing_skips(root):
    finding = network._listening(make_probe(root))
    assert finding.status is Status.SKIP


def test_ufw_active_passes(root):
    probe = make_probe(
        root,
        {("ufw", "status"): CommandResult(("ufw",), 0, "Status: active\n")},
    )
    finding = network._firewall(probe)
    assert finding.status is Status.PASS
    assert "ufw" in finding.detail


def test_all_firewall_tools_blocked_skips(root):
    probe = make_probe(
        root,
        {
            ("nft", "list", "ruleset"): CommandResult(("nft",), 1, "", "Operation not permitted"),
            ("iptables", "-S"): CommandResult(("iptables",), 4, "", "Permission denied"),
            ("ufw", "status"): CommandResult(("ufw",), 4, "", "Permission denied (you must be root)"),
            ("firewall-cmd", "--state"): CommandResult(("firewall-cmd",), 4, "", "Permission denied (polkit)"),
        },
    )
    finding = network._firewall(probe)
    assert finding.status is Status.SKIP


def test_tools_present_without_rules_fails(root):
    probe = make_probe(
        root,
        {
            ("iptables", "-S"): CommandResult(("iptables",), 0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n"),
        },
    )
    finding = network._firewall(probe)
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM


def test_no_firewall_tools_skips(root):
    finding = network._firewall(make_probe(root))
    assert finding.status is Status.SKIP


def test_module_run_smoke(root):
    probe = make_probe(root, {("ufw", "status"): CommandResult(("ufw",), 0, "Status: active")})
    findings = network.run(probe)
    assert {item.category for item in findings} == {"网络"}
