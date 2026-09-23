"""Account and privilege checks: UID 0 aliases, empty passwords, sudo, SSH keys."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "账户"

NOLOGIN_SHELLS = {
    "",
    "/bin/false",
    "/usr/bin/false",
    "/sbin/nologin",
    "/usr/sbin/nologin",
    "/bin/sync",
    "/sbin/halt",
    "/sbin/shutdown",
}


def run(probe: SystemProbe) -> list[Finding]:
    users = parse_passwd(probe)
    findings: list[Finding] = []
    findings.append(_uid_zero(users))
    findings.extend(_password_fields(probe, users))
    findings.append(_system_login_shells(users))
    findings.append(_duplicate_uids(users))
    findings.append(_sudo_nopasswd(probe))
    findings.extend(_ssh_key_perms(probe, users))
    findings.extend(_password_policy(probe))
    findings.append(_pam_quality(probe))
    findings.append(_pam_faillock(probe))
    return findings


def parse_passwd(probe: SystemProbe) -> list[dict[str, str]]:
    """Return each /etc/passwd row as a mapping."""
    rows: list[dict[str, str]] = []
    for line in probe.read_lines("/etc/passwd"):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        rows.append(
            {
                "name": parts[0],
                "password": parts[1],
                "uid": parts[2],
                "gid": parts[3],
                "home": parts[5],
                "shell": parts[6],
            }
        )
    return rows


def _uid_zero(users: list[dict[str, str]]) -> Finding:
    aliases = [user["name"] for user in users if user["uid"] == "0" and user["name"] != "root"]
    if aliases:
        return fail(
            "accounts.uid_zero",
            CATEGORY,
            Severity.CRITICAL,
            "存在 UID 为 0 的非 root 账户",
            "除 root 外还有账户具备最高权限，等同于多个 root。",
            "确认这些账户是否必要；不需要则锁定或删除，并改为普通账户。",
            ", ".join(aliases),
        )
    return ok("accounts.uid_zero", CATEGORY, "只有 root 拥有 UID 0")


def _password_fields(probe: SystemProbe, users: list[dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    blank_passwd = [user["name"] for user in users if user["password"] == ""]
    if blank_passwd:
        findings.append(
            fail(
                "accounts.passwd_blank",
                CATEGORY,
                Severity.CRITICAL,
                "/etc/passwd 中存在空密码账户",
                "口令字段为空表示登录无需密码。",
                "为这些账户设置口令或将其锁定。",
                ", ".join(blank_passwd),
            )
        )
    else:
        findings.append(ok("accounts.passwd_blank", CATEGORY, "/etc/passwd 无空密码账户"))

    if not probe.is_root and not probe.exists("/etc/shadow"):
        findings.append(
            skip(
                "accounts.empty_password",
                CATEGORY,
                "空口令检查",
                "需要 root 才能读取 /etc/shadow。",
            )
        )
        return findings

    shadow = _parse_shadow(probe)
    if shadow is None:
        findings.append(
            skip("accounts.empty_password", CATEGORY, "空口令检查", "无法读取 /etc/shadow。")
        )
        return findings
    empty = [name for name, field in shadow.items() if field == ""]
    if empty:
        findings.append(
            fail(
                "accounts.empty_password",
                CATEGORY,
                Severity.CRITICAL,
                "存在空口令账户",
                "这些账户的口令哈希为空，可无需口令登录。",
                "立即设置口令或锁定账户。",
                ", ".join(empty),
            )
        )
    else:
        findings.append(ok("accounts.empty_password", CATEGORY, "未发现空口令账户"))
    return findings


def _parse_shadow(probe: SystemProbe) -> dict[str, str] | None:
    text = probe.read_text("/etc/shadow", "")
    if not text:
        return None
    rows: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            rows[parts[0]] = parts[1]
    return rows


def _system_login_shells(users: list[dict[str, str]]) -> Finding:
    exposed = [
        user["name"]
        for user in users
        if user["shell"] not in NOLOGIN_SHELLS and user["uid"].isdigit() and int(user["uid"]) < 1000 and user["uid"] != "0"
    ]
    if exposed:
        return fail(
            "accounts.system_login_shells",
            CATEGORY,
            Severity.LOW,
            "系统账户拥有可登录 shell",
            "UID 小于 1000 的系统账户通常不应允许交互登录。",
            "将这类账户的 shell 改为 /usr/sbin/nologin，除非确有登录需求。",
            ", ".join(exposed),
        )
    return ok("accounts.system_login_shells", CATEGORY, "系统账户均不可交互登录")


def _duplicate_uids(users: list[dict[str, str]]) -> Finding:
    seen: dict[str, list[str]] = {}
    for user in users:
        seen.setdefault(user["uid"], []).append(user["name"])
    dupes = {uid: names for uid, names in seen.items() if len(names) > 1}
    if dupes:
        detail = "; ".join(f"UID {uid}: {', '.join(names)}" for uid, names in dupes.items())
        return fail(
            "accounts.duplicate_uid",
            CATEGORY,
            Severity.MEDIUM,
            "存在重复的 UID",
            "多个账户共用同一 UID，权限归属难以审计。",
            "为每个账户分配唯一 UID。",
            detail,
        )
    return ok("accounts.duplicate_uid", CATEGORY, "UID 无重复")


def _sudo_nopasswd(probe: SystemProbe) -> Finding:
    files = ["/etc/sudoers"] + probe.glob("/etc/sudoers.d/*")
    hits: list[str] = []
    for rel in files:
        for line in probe.read_lines(rel):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "NOPASSWD" in stripped:
                hits.append(f"{rel}: {stripped}")
    if hits:
        return fail(
            "accounts.sudo_nopasswd",
            CATEGORY,
            Severity.MEDIUM,
            "sudo 配置存在 NOPASSWD",
            "sudo 可无需口令执行，口令泄露风险被放大。",
            "仅在确有必要时为特定命令保留 NOPASSWD，其余要求输入口令。",
            " | ".join(hits),
        )
    return ok("accounts.sudo_nopasswd", CATEGORY, "sudo 未配置 NOPASSWD")


def _ssh_key_perms(probe: SystemProbe, users: list[dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    dir_bad: list[str] = []
    key_bad: list[str] = []
    for user in users:
        if not user["uid"].isdigit() or int(user["uid"]) < 1000:
            continue
        home = user["home"].rstrip("/") or "/"
        ssh_dir = f"{home}/.ssh"
        info = probe.info(f"{ssh_dir}/authorized_keys")
        if info is not None and info.any_write():
            key_bad.append(f"{ssh_dir}/authorized_keys ({info.perm_text})")
        dir_info = probe.info(ssh_dir)
        if dir_info is not None and dir_info.is_dir and dir_info.perm & 0o077:
            dir_bad.append(f"{ssh_dir} ({dir_info.perm_text})")
    if key_bad:
        findings.append(
            fail(
                "accounts.ssh_key_writable",
                CATEGORY,
                Severity.HIGH,
                "authorized_keys 可被他人写入",
                "组或其他用户可写 authorized_keys，可能被植入公钥。",
                "执行 chmod 600 修正权限，并确认文件内容可信。",
                ", ".join(key_bad),
            )
        )
    else:
        findings.append(ok("accounts.ssh_key_writable", CATEGORY, "authorized_keys 权限正常"))
    if dir_bad:
        findings.append(
            fail(
                "accounts.ssh_dir_perms",
                CATEGORY,
                Severity.MEDIUM,
                "~/.ssh 目录权限过宽",
                "目录允许组或其他用户访问。",
                "执行 chmod 700 ~/.ssh 收紧权限。",
                ", ".join(dir_bad),
            )
        )
    else:
        findings.append(ok("accounts.ssh_dir_perms", CATEGORY, ".ssh 目录权限正常"))
    return findings


PAM_PASSWORD_FILES = [
    "/etc/pam.d/common-password",
    "/etc/pam.d/system-auth",
]

PAM_AUTH_FILES = [
    "/etc/pam.d/common-auth",
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
]


def _read_login_defs(probe: SystemProbe) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in probe.read_lines("/etc/login.defs"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            values.setdefault(parts[0], parts[1])
    return values


def _password_policy(probe: SystemProbe) -> list[Finding]:
    if not probe.exists("/etc/login.defs"):
        return [
            skip(
                "accounts.password_policy",
                CATEGORY,
                "口令有效期策略",
                "未找到 /etc/login.defs，无法评估口令有效期策略。",
            )
        ]
    values = _read_login_defs(probe)
    findings: list[Finding] = []
    max_days_raw = values.get("PASS_MAX_DAYS")
    if max_days_raw is None:
        findings.append(
            fail(
                "accounts.password_policy",
                CATEGORY,
                Severity.MEDIUM,
                "未设置口令最长有效期",
                "login.defs 未定义 PASS_MAX_DAYS，口令可能长期不更换。",
                "在 /etc/login.defs 设置 PASS_MAX_DAYS 90 或更小。",
            )
        )
    else:
        try:
            max_days = int(max_days_raw)
        except ValueError:
            max_days = -1
        if max_days <= 0 or max_days > 90:
            findings.append(
                fail(
                    "accounts.password_policy",
                    CATEGORY,
                    Severity.MEDIUM,
                    "口令最长有效期过长",
                    f"PASS_MAX_DAYS 当前为 {max_days_raw}，口令长期不更换会放大泄露风险。",
                    "在 /etc/login.defs 设置 PASS_MAX_DAYS 90 或更小。",
                    f"PASS_MAX_DAYS {max_days_raw}",
                )
            )
        else:
            findings.append(
                ok("accounts.password_policy", CATEGORY, "口令有效期策略合理", f"PASS_MAX_DAYS {max_days_raw}")
            )

    umask = values.get("UMASK")
    if umask in {"022", "002", None}:
        findings.append(
            fail(
                "accounts.default_umask",
                CATEGORY,
                Severity.LOW,
                "默认 umask 过于宽松",
                "登录默认 umask 为 022 时，用户新建文件默认组可读，易造成敏感文件泄露。",
                "在 /etc/login.defs 设置 UMASK 027 或 077。",
                "UMASK 022" if umask is None else f"UMASK {umask}",
            )
        )
    else:
        findings.append(ok("accounts.default_umask", CATEGORY, "默认 umask 已收紧", f"UMASK {umask}"))
    return findings


def _pam_quality(probe: SystemProbe) -> Finding:
    enabled = False
    for rel in PAM_PASSWORD_FILES:
        for line in probe.read_lines(rel):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "pam_pwquality.so" in stripped:
                enabled = True
                break
        if enabled:
            break
    if not enabled:
        return fail(
            "accounts.pam_pwquality",
            CATEGORY,
            Severity.MEDIUM,
            "未启用口令复杂度校验",
            "PAM 未加载 pam_pwquality，弱口令（如 123456）可直接通过设置。",
            "安装 libpwquality 并在 PAM password 栈启用 pam_pwquality.so。",
        )
    conf = probe.read_text("/etc/security/pwquality.conf", "")
    minlen: int | None = None
    for line in conf.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("minlen"):
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                try:
                    minlen = int(parts[1].strip())
                except ValueError:
                    minlen = None
                break
    if minlen is not None and minlen < 8:
        return fail(
            "accounts.pam_pwquality",
            CATEGORY,
            Severity.LOW,
            "口令最小长度要求偏低",
            f"pwquality minlen 当前为 {minlen}，低于 8 位。",
            "在 /etc/security/pwquality.conf 设置 minlen 12 或至少 8。",
            f"minlen = {minlen}",
        )
    return ok("accounts.pam_pwquality", CATEGORY, "口令复杂度校验已启用")


def _pam_faillock(probe: SystemProbe) -> Finding:
    for rel in PAM_AUTH_FILES:
        for line in probe.read_lines(rel):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "pam_faillock.so" in stripped:
                return ok("accounts.pam_faillock", CATEGORY, "登录失败锁定已启用", rel)
    if not any(probe.exists(rel) for rel in PAM_AUTH_FILES):
        return skip(
            "accounts.pam_faillock",
            CATEGORY,
            "登录失败锁定检查",
            "未找到 PAM 认证配置文件。",
        )
    return fail(
        "accounts.pam_faillock",
        CATEGORY,
        Severity.LOW,
        "未配置登录失败锁定",
        "口令可被无限次尝试，暴力破解不受限制。",
        "在 PAM auth 栈启用 pam_faillock.so，例如 deny=5 unlock_time=900。",
    )
