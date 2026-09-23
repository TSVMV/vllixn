"""Tests for account and privilege checks."""

from __future__ import annotations

from conftest import make_probe, write

from vllixn.checks import accounts
from vllixn.model import Severity, Status

PASSWD_BASE = "\n".join(
    [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
    ]
)


def test_uid_zero_alias_fails(root):
    write(root, "/etc/passwd", PASSWD_BASE + "\ntoor:x:0:0:backdoor:/root:/bin/bash")
    finding = accounts._uid_zero(accounts.parse_passwd(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.CRITICAL
    assert "toor" in finding.evidence


def test_uid_zero_clean(root):
    write(root, "/etc/passwd", PASSWD_BASE)
    finding = accounts._uid_zero(accounts.parse_passwd(make_probe(root)))
    assert finding.status is Status.PASS


def test_empty_password_detected_as_root(root):
    write(root, "/etc/passwd", PASSWD_BASE)
    write(root, "/etc/shadow", "root:$6$hash:1:0:99:7:::\nalice::1:0:99:7:::\n")
    findings = accounts._password_fields(make_probe(root), accounts.parse_passwd(make_probe(root)))
    by_id = {item.id: item for item in findings}
    assert by_id["accounts.empty_password"].status is Status.FAIL
    assert "alice" in by_id["accounts.empty_password"].evidence


def test_empty_password_skipped_without_root(root):
    write(root, "/etc/passwd", PASSWD_BASE)
    findings = accounts._password_fields(
        make_probe(root, uid=1000), accounts.parse_passwd(make_probe(root, uid=1000))
    )
    assert all(item.id != "accounts.empty_password" or item.status is Status.SKIP for item in findings)


def test_sudo_nopasswd_found(root):
    write(root, "/etc/passwd", PASSWD_BASE)
    write(root, "/etc/sudoers.d/admin", "alice ALL=(ALL) NOPASSWD: ALL\n")
    finding = accounts._sudo_nopasswd(make_probe(root))
    assert finding.status is Status.FAIL
    assert "NOPASSWD" in finding.evidence


def test_duplicate_uid(root):
    write(root, "/etc/passwd", PASSWD_BASE + "\ndup:x:1000:1000:Dup:/home/dup:/bin/bash")
    finding = accounts._duplicate_uids(accounts.parse_passwd(make_probe(root)))
    assert finding.status is Status.FAIL
    assert "UID 1000" in finding.evidence


def test_system_account_with_login_shell(root):
    rows = "\n".join(
        [
            "root:x:0:0:root:/root:/bin/bash",
            "svc:x:999:999:svc:/srv:/bin/bash",
        ]
    )
    write(root, "/etc/passwd", rows)
    finding = accounts._system_login_shells(accounts.parse_passwd(make_probe(root)))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_writable_authorized_keys(root):
    write(root, "/etc/passwd", PASSWD_BASE)
    write(root, "/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA demo\n", mode=0o666)
    finding_by_id = {
        item.id: item
        for item in accounts._ssh_key_perms(make_probe(root), accounts.parse_passwd(make_probe(root)))
    }
    assert finding_by_id["accounts.ssh_key_writable"].status is Status.FAIL
    assert finding_by_id["accounts.ssh_key_writable"].severity is Severity.HIGH


def test_module_run_smoke(root):
    write(root, "/etc/passwd", PASSWD_BASE)
    findings = accounts.run(make_probe(root))
    assert findings
    assert all(isinstance(item.id, str) and item.category == "账户" for item in findings)


def test_password_policy_too_long_fails(root):
    write(root, "/etc/login.defs", "PASS_MAX_DAYS 999\nUMASK 027\n")
    findings = {item.id: item for item in accounts._password_policy(make_probe(root))}
    assert findings["accounts.password_policy"].status is Status.FAIL
    assert findings["accounts.password_policy"].severity is Severity.MEDIUM


def test_password_policy_reasonable_passes(root):
    write(root, "/etc/login.defs", "PASS_MAX_DAYS 90\nUMASK 027\n")
    findings = {item.id: item for item in accounts._password_policy(make_probe(root))}
    assert findings["accounts.password_policy"].status is Status.PASS
    assert findings["accounts.default_umask"].status is Status.PASS


def test_umask_022_flagged_low(root):
    write(root, "/etc/login.defs", "PASS_MAX_DAYS 90\nUMASK 022\n")
    findings = {item.id: item for item in accounts._password_policy(make_probe(root))}
    assert findings["accounts.default_umask"].status is Status.FAIL
    assert findings["accounts.default_umask"].severity is Severity.LOW


def test_pam_pwquality_missing_fails(root):
    write(root, "/etc/pam.d/common-password", "password requisite pam_unix.so\n")
    assert accounts._pam_quality(make_probe(root)).status is Status.FAIL


def test_pam_pwquality_enabled_passes(root):
    write(root, "/etc/pam.d/common-password", "password requisite pam_pwquality.so retry=3\n")
    assert accounts._pam_quality(make_probe(root)).status is Status.PASS


def test_pam_pwquality_short_minlen_low(root):
    write(root, "/etc/pam.d/common-password", "password requisite pam_pwquality.so\n")
    write(root, "/etc/security/pwquality.conf", "minlen = 6\n")
    finding = accounts._pam_quality(make_probe(root))
    assert finding.status is Status.FAIL
    assert finding.severity is Severity.LOW


def test_pam_faillock_missing_fails(root):
    write(root, "/etc/pam.d/common-auth", "auth required pam_unix.so\n")
    assert accounts._pam_faillock(make_probe(root)).status is Status.FAIL


def test_pam_faillock_enabled_passes(root):
    write(root, "/etc/pam.d/common-auth", "auth required pam_faillock.so deny=5\n")
    assert accounts._pam_faillock(make_probe(root)).status is Status.PASS


def test_pam_faillock_no_pam_files_skips(root):
    assert accounts._pam_faillock(make_probe(root)).status is Status.SKIP
