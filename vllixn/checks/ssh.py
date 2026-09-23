"""SSH server configuration checks (sshd_config and drop-in files)."""

from __future__ import annotations

from pathlib import Path

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "SSH"

MAIN_CONFIG = "/etc/ssh/sshd_config"


def run(probe: SystemProbe) -> list[Finding]:
    if not probe.exists(MAIN_CONFIG):
        return [
            skip(
                "ssh.installed",
                CATEGORY,
                "SSH 服务检查",
                "未找到 /etc/ssh/sshd_config，可能未安装 OpenSSH 服务。",
            )
        ]
    options = parse_options(probe)
    return [
        _permit_root_login(options),
        _password_auth(options),
        _permit_empty_passwords(options),
        _tcp_forwarding(options),
        _x11_forwarding(options),
        _max_auth_tries(options),
        _protocol(options),
        _login_grace_time(options),
        _client_alive(options),
        _access_restrict(options),
        _hostbased(options),
    ]


def parse_options(probe: SystemProbe) -> dict[str, str]:
    """Return effective sshd options. OpenSSH keeps the first value seen."""
    options: dict[str, str] = {}
    visited: set[str] = set()

    def load(rel: str) -> None:
        if rel in visited:
            return
        visited.add(rel)
        for raw in probe.read_lines(rel):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            keyword = parts[0].lower()
            value = parts[1].strip() if len(parts) > 1 else ""
            if keyword == "include":
                for target in _resolve_include(probe, rel, value):
                    load(target)
                continue
            if keyword and keyword not in options:
                options[keyword] = value

    load(MAIN_CONFIG)
    return options


def _resolve_include(probe: SystemProbe, rel: str, pattern: str) -> list[str]:
    if not pattern:
        return []
    if not pattern.startswith("/"):
        pattern = f"{Path(rel).parent!s}/{pattern}"
    return probe.glob(pattern)


def _permit_root_login(options: dict[str, str]) -> Finding:
    value = options.get("permitrootlogin", "").lower()
    if value in {"yes", "without-password", "prohibit-password", "forced-commands-only"}:
        severity = Severity.HIGH if value == "yes" else Severity.LOW
        return fail(
            "ssh.permit_root_login",
            CATEGORY,
            severity,
            "允许 root 通过 SSH 登录",
            f"PermitRootLogin 当前为 {value}。",
            "建议设为 no，改用普通账户登录后再 sudo。",
            f"PermitRootLogin {value}",
        )
    return ok("ssh.permit_root_login", CATEGORY, "禁止 root 通过 SSH 登录")


def _password_auth(options: dict[str, str]) -> Finding:
    value = options.get("passwordauthentication", "yes").lower()
    if value not in {"no", "false", "off"}:
        return fail(
            "ssh.password_auth",
            CATEGORY,
            Severity.HIGH,
            "启用了 SSH 口令认证",
            "口令认证易受暴力破解与撞库影响。",
            "改用公钥认证并将 PasswordAuthentication 设为 no。",
            f"PasswordAuthentication {value}",
        )
    return ok("ssh.password_auth", CATEGORY, "已关闭 SSH 口令认证")


def _permit_empty_passwords(options: dict[str, str]) -> Finding:
    value = options.get("permitemptypasswords", "no").lower()
    if value not in {"no", "false", "off"}:
        return fail(
            "ssh.permit_empty_passwords",
            CATEGORY,
            Severity.CRITICAL,
            "允许空口令登录",
            "PermitEmptyPasswords 已开启。",
            "将 PermitEmptyPasswords 设为 no。",
            f"PermitEmptyPasswords {value}",
        )
    return ok("ssh.permit_empty_passwords", CATEGORY, "未允许空口令登录")


def _tcp_forwarding(options: dict[str, str]) -> Finding:
    value = options.get("allowtcpforwarding", "yes").lower()
    if value not in {"no", "false", "off"}:
        return fail(
            "ssh.allow_tcp_forwarding",
            CATEGORY,
            Severity.MEDIUM,
            "允许 SSH 端口转发",
            "端口转发可被用于绕过网络边界。",
            "如无需求，将 AllowTcpForwarding 设为 no。",
            f"AllowTcpForwarding {value}",
        )
    return ok("ssh.allow_tcp_forwarding", CATEGORY, "已关闭 SSH 端口转发")


def _x11_forwarding(options: dict[str, str]) -> Finding:
    value = options.get("x11forwarding", "no").lower()
    if value in {"yes", "true", "on"}:
        return fail(
            "ssh.x11_forwarding",
            CATEGORY,
            Severity.LOW,
            "启用了 X11 转发",
            "X11 转发扩大攻击面且易被滥用。",
            "将 X11Forwarding 设为 no。",
            f"X11Forwarding {value}",
        )
    return ok("ssh.x11_forwarding", CATEGORY, "已关闭 X11 转发")


def _max_auth_tries(options: dict[str, str]) -> Finding:
    raw = options.get("maxauthtries", "6")
    try:
        tries = int(raw)
    except ValueError:
        return skip("ssh.max_auth_tries", CATEGORY, "MaxAuthTries 解析失败", raw)
    if tries > 6:
        return fail(
            "ssh.max_auth_tries",
            CATEGORY,
            Severity.LOW,
            "MaxAuthTries 偏大",
            f"当前为 {tries}，允许多次口令尝试。",
            "建议设为 4 或更低。",
            f"MaxAuthTries {tries}",
        )
    return ok("ssh.max_auth_tries", CATEGORY, "MaxAuthTries 设置合理")


def _protocol(options: dict[str, str]) -> Finding:
    raw = options.get("protocol", "2")
    if "1" in [part.strip() for part in raw.split(",")]:
        return fail(
            "ssh.protocol",
            CATEGORY,
            Severity.CRITICAL,
            "启用了 SSH 协议 1",
            "协议 1 存在已知缺陷，已废弃。",
            "仅保留协议 2。",
            f"Protocol {raw}",
        )
    return ok("ssh.protocol", CATEGORY, "未启用过时的 SSH 协议 1")


def _login_grace_time(options: dict[str, str]) -> Finding:
    raw = options.get("logingracetime", "120")
    try:
        grace = int(raw)
    except ValueError:
        return skip("ssh.login_grace_time", CATEGORY, "LoginGraceTime 解析失败", raw)
    if grace > 60:
        return fail(
            "ssh.login_grace_time",
            CATEGORY,
            Severity.LOW,
            "SSH 认证宽限时间偏长",
            f"LoginGraceTime 当前为 {grace} 秒，未认证连接存活越久越利于资源占用与探测。",
            "建议设为 60 或更小。",
            f"LoginGraceTime {grace}",
        )
    return ok("ssh.login_grace_time", CATEGORY, "SSH 认证宽限时间合理")


def _client_alive(options: dict[str, str]) -> Finding:
    raw = options.get("clientaliveinterval", "0")
    try:
        interval = int(raw)
    except ValueError:
        return skip("ssh.client_alive", CATEGORY, "ClientAliveInterval 解析失败", raw)
    if interval <= 0:
        return fail(
            "ssh.client_alive",
            CATEGORY,
            Severity.LOW,
            "SSH 空闲会话不超时",
            "未配置 ClientAliveInterval，断开的空闲会话将一直占用。",
            "设置 ClientAliveInterval 300 与 ClientAliveCountMax 3 之类的空闲超时。",
            f"ClientAliveInterval {raw}",
        )
    if interval > 900:
        return fail(
            "ssh.client_alive",
            CATEGORY,
            Severity.LOW,
            "SSH 空闲会话超时偏长",
            f"ClientAliveInterval 当前为 {interval} 秒。",
            "建议设为 900 以内的空闲检测间隔。",
            f"ClientAliveInterval {interval}",
        )
    return ok("ssh.client_alive", CATEGORY, "SSH 空闲会话超时已配置")


def _access_restrict(options: dict[str, str]) -> Finding:
    has_policy = any(
        options.get(key)
        for key in ("allowusers", "allowgroups", "denyusers", "denygroups")
    )
    if has_policy:
        return ok("ssh.access_restrict", CATEGORY, "已配置 SSH 登录用户范围限制")
    return fail(
        "ssh.access_restrict",
        CATEGORY,
        Severity.LOW,
        "未限制 SSH 可登录用户",
        "任何有效账户都可以尝试 SSH 登录，包括服务账户。",
        "配置 AllowGroups 或 AllowUsers，仅允许必要的管理账户登录。",
    )


def _hostbased(options: dict[str, str]) -> Finding:
    value = options.get("hostbasedauthentication", "no").lower()
    if value in {"yes", "true", "on"}:
        return fail(
            "ssh.hostbased",
            CATEGORY,
            Severity.MEDIUM,
            "启用了基于主机的认证",
            "HostbasedAuthentication 信任来源主机，主机密钥失陷即被横向利用。",
            "将 HostbasedAuthentication 设为 no。",
            f"HostbasedAuthentication {value}",
        )
    return ok("ssh.hostbased", CATEGORY, "未启用基于主机的认证")
