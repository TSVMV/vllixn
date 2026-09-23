"""Kernel parameter hardening checks via /proc/sys."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "内核"

# (sysctl rel path, accepted values, human label)
NET_HARDENING: list[tuple[str, set[str], str]] = [
    ("net/ipv4/conf/all/accept_redirects", {"0"}, "拒绝 ICMP 重定向"),
    ("net/ipv4/conf/default/accept_redirects", {"0"}, "拒绝 ICMP 重定向（default）"),
    ("net/ipv4/conf/all/send_redirects", {"0"}, "不发送 ICMP 重定向"),
    ("net/ipv4/conf/all/accept_source_route", {"0"}, "拒绝源路由包"),
    ("net/ipv4/conf/all/rp_filter", {"1"}, "启用反向路径过滤"),
    ("net/ipv4/icmp_echo_ignore_broadcasts", {"1"}, "忽略广播 ICMP"),
    ("net/ipv4/icmp_ignore_bogus_error_responses", {"1"}, "忽略伪造 ICMP 错误"),
    ("net/ipv4/tcp_syncookies", {"1"}, "SYN Cookie 抗洪泛"),
    ("net/ipv6/conf/all/accept_redirects", {"0"}, "拒绝 IPv6 ICMP 重定向"),
]

INFO_LEAK: list[tuple[str, set[str], str]] = [
    ("kernel/kptr_restrict", {"1", "2"}, "限制内核指针泄露"),
    ("kernel/dmesg_restrict", {"1"}, "限制非特权读取 dmesg"),
    ("kernel/sysrq", {"0"}, "关闭 Magic SysRq"),
    ("kernel/yama/ptrace_scope", {"1", "2", "3"}, "限制 ptrace 附加范围"),
]

FS_PROTECT: list[tuple[str, set[str], str]] = [
    ("fs/protected_symlinks", {"1"}, "限制符号链接跟随"),
    ("fs/protected_hardlinks", {"1"}, "限制硬链接创建"),
    ("fs/protected_regular", {"1", "2"}, "保护常规文件写入"),
    ("fs/suid_dumpable", {"0"}, "禁止 SUID 程序转储"),
]


def run(probe: SystemProbe) -> list[Finding]:
    return [
        _group(
            probe,
            "kernel.net_hardening",
            Severity.LOW,
            "网络加固参数未收紧",
            "网络加固参数正常",
            "以下内核参数削弱了对 ICMP 重定向、源路由等网络攻击的防御。",
            "通过 sysctl 持久化配置收紧这些参数（写入 /etc/sysctl.d/ 下配置文件）。",
            NET_HARDENING,
        ),
        _group(
            probe,
            "kernel.info_leak",
            Severity.MEDIUM,
            "信息泄露相关参数未收紧",
            "信息泄露防护参数正常",
            "以下参数允许非特权用户读取内核地址或日志，便于攻击者侦察。",
            "在 /etc/sysctl.d/ 中设置 kptr_restrict、dmesg_restrict、sysrq、ptrace_scope。",
            INFO_LEAK,
        ),
        _aslr(probe),
        _group(
            probe,
            "kernel.fs_protect",
            Severity.LOW,
            "文件系统保护参数未启用",
            "文件系统保护参数正常",
            "以下参数用于缓解符号链接竞争与 SUID 转储等本地提权手法。",
            "在 /etc/sysctl.d/ 中启用 protected_symlinks/protected_hardlinks 等保护。",
            FS_PROTECT,
        ),
    ]


def _group(
    probe: SystemProbe,
    check_id: str,
    severity: Severity,
    title: str,
    ok_title: str,
    detail: str,
    advice: str,
    params: list[tuple[str, set[str], str]],
) -> Finding:
    bad: list[str] = []
    unreadable = 0
    for rel, accepted, label in params:
        value = probe.read_text(f"/proc/sys/{rel}").strip()
        if not value:
            unreadable += 1
            continue
        if value not in accepted:
            bad.append(f"{rel.replace('/', '.')} = {value}（期望 {'/'.join(sorted(accepted))}，{label}）")
    if unreadable == len(params):
        return skip(
            check_id,
            CATEGORY,
            title,
            "无法读取对应的 /proc/sys 参数（可能是容器或非 Linux 环境）。",
        )
    if bad:
        return fail(check_id, CATEGORY, severity, title, detail, advice, "; ".join(bad))
    return ok(check_id, CATEGORY, ok_title)


def _aslr(probe: SystemProbe) -> Finding:
    value = probe.read_text("/proc/sys/kernel/randomize_va_space").strip()
    if not value:
        return skip(
            "kernel.aslr",
            CATEGORY,
            "地址空间随机化检查",
            "无法读取 /proc/sys/kernel/randomize_va_space。",
        )
    if value == "2":
        return ok("kernel.aslr", CATEGORY, "地址空间随机化已完全开启")
    detail = (
        "randomize_va_space=1 仅部分随机化，堆栈与库的布局仍可预测。"
        if value == "1"
        else "randomize_va_space=0 表示地址空间随机化被完全关闭。"
    )
    severity = Severity.LOW if value == "1" else Severity.HIGH
    return fail(
        "kernel.aslr",
        CATEGORY,
        severity,
        "地址空间随机化未完全开启",
        detail,
        "在 /etc/sysctl.d/ 中设置 kernel.randomize_va_space=2。",
        f"randomize_va_space = {value}",
    )
