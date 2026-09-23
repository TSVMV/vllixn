"""Audit and hardening layer checks: MAC, auditd and time sync."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "审计"

NTP_CONFIGS = [
    "/etc/chrony.conf",
    "/etc/chrony/chrony.conf",
    "/etc/ntp.conf",
    "/etc/systemd/timesyncd.conf",
]


def run(probe: SystemProbe) -> list[Finding]:
    return [_mac(probe), _auditd(probe), _time_sync(probe), _persistent_logs(probe)]


def _mac(probe: SystemProbe) -> Finding:
    result = probe.command(["getenforce"])
    if result.ok:
        mode = result.stdout.strip()
        if mode == "Enforcing":
            return ok("audit.mac", CATEGORY, "SELinux 处于强制模式")
        if mode == "Permissive":
            return fail(
                "audit.mac",
                CATEGORY,
                Severity.MEDIUM,
                "SELinux 处于宽容模式",
                "Permissive 模式只记录违规行为，没有实际拦截。",
                "排查 AVC 拒绝日志后执行 setenforce 1，并持久化为 enforcing。",
                mode,
            )
    apparmor = probe.read_text("/sys/module/apparmor/parameters/enabled").strip()
    if apparmor == "Y":
        return ok("audit.mac", CATEGORY, "AppArmor 已启用")
    if probe.exists("/etc/selinux/config") or probe.exists("/etc/apparmor.d"):
        return skip(
            "audit.mac",
            CATEGORY,
            "强制访问控制检查",
            "检测到 MAC 配置文件，但无法确认运行状态。",
        )
    return fail(
        "audit.mac",
        CATEGORY,
        Severity.LOW,
        "未检测到 SELinux 或 AppArmor",
        "主机缺少强制访问控制层，进程越权后影响范围更大。",
        "安装并启用 SELinux 或 AppArmor，为关键服务配置Profile。",
    )


def _auditd(probe: SystemProbe) -> Finding:
    result = probe.command(["auditctl", "-s"])
    if result.ok:
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "enabled":
                if len(parts) >= 2 and parts[1] in {"1", "2"}:
                    return ok("audit.auditd", CATEGORY, "auditd 审计已启用")
                return fail(
                    "audit.auditd",
                    CATEGORY,
                    Severity.MEDIUM,
                    "auditd 已安装但未启用",
                    "审计子系统处于关闭状态，安全事件不会被记录。",
                    "执行 systemctl enable --now auditd，并部署基础审计规则。",
                    line.strip(),
                )
        return skip(
            "audit.auditd",
            CATEGORY,
            "auditd 审计检查",
            "auditctl 输出格式无法解析。",
        )
    if probe.exists("/etc/audit/auditd.conf"):
        return skip(
            "audit.auditd",
            CATEGORY,
            "auditd 审计检查",
            "auditd 已安装，但 auditctl 需要更高权限。",
        )
    return fail(
        "audit.auditd",
        CATEGORY,
        Severity.LOW,
        "未检测到 auditd 审计框架",
        "缺少系统调用级审计能力，入侵行为难以追溯。",
        "安装 audit 与 auditd 软件包，启用服务并配置基础规则。",
    )


def _time_sync(probe: SystemProbe) -> Finding:
    result = probe.command(["timedatectl"])
    if result.ok:
        for line in result.stdout.splitlines():
            if "synchronized" in line.lower():
                if line.strip().lower().endswith("yes"):
                    return ok("audit.time_sync", CATEGORY, "系统时间已同步")
                return fail(
                    "audit.time_sync",
                    CATEGORY,
                    Severity.LOW,
                    "系统时间未同步",
                    "时间漂移会破坏日志关联分析，也让证书校验变脆。",
                    "启用 systemd-timesyncd 或安装 chrony 进行 NTP 同步。",
                    line.strip(),
                )
    for rel in NTP_CONFIGS:
        if probe.exists(rel):
            return skip(
                "audit.time_sync",
                CATEGORY,
                "时间同步检查",
                f"检测到配置文件 {rel}，但无法确认实际同步状态。",
            )
    if result.ok:
        return fail(
            "audit.time_sync",
            CATEGORY,
            Severity.LOW,
            "未配置时间同步",
            "未发现 NTP 配置文件，timedatectl 也未报告时间同步。",
            "启用 systemd-timesyncd 或安装 chrony 并指向可信 NTP 源。",
        )
    return skip(
        "audit.time_sync",
        CATEGORY,
        "时间同步检查",
        "timedatectl 不可用且未发现 NTP 配置文件。",
    )


def _persistent_logs(probe: SystemProbe) -> Finding:
    if probe.is_dir("/var/log/journal"):
        return ok("audit.persistent_logs", CATEGORY, "journald 日志已持久化", "/var/log/journal")
    for rel in ("/etc/rsyslog.conf", "/etc/syslog-ng.conf"):
        if probe.exists(rel):
            return ok("audit.persistent_logs", CATEGORY, "检测到持久化 syslog 服务", rel)
    return fail(
        "audit.persistent_logs",
        CATEGORY,
        Severity.LOW,
        "日志仅存于内存",
        "未发现 journald 持久化目录或 rsyslog/syslog-ng 配置，重启后日志全部丢失，无法事后追溯。",
        "创建 /var/log/journal 启用 journald 持久化，或安装配置 rsyslog。",
    )
