"""Tests for SSH configuration checks."""

from __future__ import annotations

from conftest import make_probe, write

from vllixn.checks import ssh
from vllixn.model import Severity, Status


def test_missing_config_skips(root):
    findings = ssh.run(make_probe(root))
    assert len(findings) == 1
    assert findings[0].status is Status.SKIP


def test_permit_root_login_yes(root):
    write(root, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    finding = ssh._permit_root_login(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH


def test_permit_root_login_prohibit_is_low(root):
    write(root, "/etc/ssh/sshd_config", "PermitRootLogin prohibit-password\n")
    finding = ssh._permit_root_login(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_include_dropin_resolution(root):
    write(
        root,
        "/etc/ssh/sshd_config",
        "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n",
    )
    write(root, "/etc/ssh/sshd_config.d/50-hardening.conf", "PasswordAuthentication no\n")
    options = ssh.parse_options(make_probe(root))
    assert options["passwordauthentication"] == "no"


def test_password_auth_default_fails(root):
    write(root, "/etc/ssh/sshd_config", "Port 22\n")
    finding = ssh._password_auth(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.HIGH


def test_permit_empty_passwords_critical(root):
    write(root, "/etc/ssh/sshd_config", "PermitEmptyPasswords yes\n")
    finding = ssh._permit_empty_passwords(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.CRITICAL


def test_max_auth_tries_too_big(root):
    write(root, "/etc/ssh/sshd_config", "MaxAuthTries 10\n")
    finding = ssh._max_auth_tries(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL


def test_first_value_wins(root):
    write(root, "/etc/ssh/sshd_config", "PermitRootLogin no\nPermitRootLogin yes\n")
    finding = ssh._permit_root_login(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.PASS


def test_protocol_1_critical(root):
    write(root, "/etc/ssh/sshd_config", "Protocol 2,1\n")
    finding = ssh._protocol(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.CRITICAL


def test_login_grace_time_too_long(root):
    write(root, "/etc/ssh/sshd_config", "LoginGraceTime 500\n")
    assert ssh._login_grace_time(ssh.parse_options(make_probe(root))).status is Status.FAIL


def test_login_grace_time_default_flagged(root):
    write(root, "/etc/ssh/sshd_config", "Port 22\n")
    finding = ssh._login_grace_time(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_client_alive_default_flagged(root):
    write(root, "/etc/ssh/sshd_config", "Port 22\n")
    assert ssh._client_alive(ssh.parse_options(make_probe(root))).status is Status.FAIL


def test_client_alive_configured_passes(root):
    write(root, "/etc/ssh/sshd_config", "ClientAliveInterval 300\n")
    assert ssh._client_alive(ssh.parse_options(make_probe(root))).status is Status.PASS


def test_access_restrict_missing_flagged(root):
    write(root, "/etc/ssh/sshd_config", "Port 22\n")
    assert ssh._access_restrict(ssh.parse_options(make_probe(root))).status is Status.FAIL


def test_access_restrict_allowgroups_passes(root):
    write(root, "/etc/ssh/sshd_config", "AllowGroups admins\n")
    assert ssh._access_restrict(ssh.parse_options(make_probe(root))).status is Status.PASS


def test_hostbased_enabled_medium(root):
    write(root, "/etc/ssh/sshd_config", "HostbasedAuthentication yes\n")
    finding = ssh._hostbased(ssh.parse_options(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.MEDIUM
