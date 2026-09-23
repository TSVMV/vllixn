"""Enabled systemd units and legacy startup script checks."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "服务"

# Unit name prefixes that provide plain-text or legacy remote access.
RISKY_UNITS: dict[str, str] = {
    "telnet": "Telnet 明文远程登录",
    "rsh": "RSH 明文远程执行",
    "rlogin": "RLogin 明文远程登录",
    "rexec": "RExec 明文远程执行",
    "tftp": "TFTP 明文文件传输",
    "xinetd": "xinetd 超级守护进程",
    "chargen": "chargen 字符生成服务",
    "daytime": "daytime 时间服务",
    "echo": "echo 回显服务",
    "discard": "discard 丢弃服务",
    "vsftpd": "FTP 明文文件传输",
    "wu-ftpd": "FTP 明文文件传输",
}

SYSTEMCTL_ARGS = [
    "systemctl",
    "list-unit-files",
    "--type=service",
    "--type=socket",
    "--state=enabled",
    "--no-legend",
]


def run(probe: SystemProbe) -> list[Finding]:
    return [_enabled_units(probe), _rc_local(probe), _cron_access(probe)]


def parse_unit_list(text: str) -> list[str]:
    """Extract unit names from ``systemctl list-unit-files --no-legend``."""
    units: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if parts:
            units.append(parts[0])
    return units


def _risky_units(units: list[str]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for unit in units:
        base = unit.split(".")[0].rsplit("@", 1)[0]
        reason = RISKY_UNITS.get(base)
        if reason:
            hits.append((unit, reason))
    return hits


def _enabled_units(probe: SystemProbe) -> Finding:
    result = probe.command(SYSTEMCTL_ARGS)
    if not result.ok:
        detail = result.stderr.strip() or "systemctl 不可用，无法枚举开机启用的服务。"
        return skip("services.enabled_units", CATEGORY, "开机启用服务检查", detail)
    units = parse_unit_list(result.stdout)
    hits = _risky_units(units)
    if hits:
        names = "、".join(f"{unit}（{reason}）" for unit, reason in hits)
        return fail(
            "services.enabled_units",
            CATEGORY,
            Severity.HIGH,
            "开机启用了高风险服务",
            "以下服务提供明文传输或已被淘汰的远程访问能力，且随开机自启。",
            "执行 systemctl disable --now <服务名> 关闭；确需远程访问时改用 SSH 通道。",
            names,
        )
    return ok(
        "services.enabled_units",
        CATEGORY,
        f"开机启用的服务 {len(units)} 个，未发现高风险项",
    )


def _rc_local(probe: SystemProbe) -> Finding:
    info = probe.info("/etc/rc.local", follow=False)
    if info is None:
        return ok("services.rc_local", CATEGORY, "未发现 /etc/rc.local 自启动脚本")
    if not info.is_symlink and info.perm & 0o111:
        return fail(
            "services.rc_local",
            CATEGORY,
            Severity.LOW,
            "存在可执行的 /etc/rc.local",
            "rc.local 中的命令以 root 身份在开机时运行，常被忽略且不纳入服务管理。",
            "核对脚本内容确属必要；可迁移为 systemd unit 便于审计。",
            info.perm_text,
        )
    return ok("services.rc_local", CATEGORY, "/etc/rc.local 存在但不可执行")


def _cron_access(probe: SystemProbe) -> Finding:
    deny_hits = [rel for rel in ("/etc/cron.deny", "/etc/at.deny") if probe.exists(rel)]
    allow_hits = [rel for rel in ("/etc/cron.allow", "/etc/at.allow") if probe.exists(rel)]
    if deny_hits:
        return fail(
            "services.cron_access",
            CATEGORY,
            Severity.MEDIUM,
            "计划任务仍使用黑名单模式",
            "存在 cron.deny/at.deny 时任何用户默认可用，仅排除黑名单成员，收口不严。",
            "删除黑名单文件，改用仅含必要账户的 cron.allow/at.allow（权限 600 root:root）。",
            "、".join(deny_hits),
        )
    if not allow_hits:
        return fail(
            "services.cron_access",
            CATEGORY,
            Severity.MEDIUM,
            "计划任务未配置白名单",
            "未配置 cron.allow/at.allow，任何有效账户都能安排定时任务。",
            "建立仅含必要账户的 cron.allow 与 at.allow。",
        )
    return ok("services.cron_access", CATEGORY, "计划任务已用白名单限制", "、".join(allow_hits))
