"""Filesystem permission checks for sensitive files, dirs and SUID binaries."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "文件权限"

# SUID/SGID binaries whose presence usually grants an easy privilege escalation.
RISKY_SUID = {
    "bash",
    "sh",
    "dash",
    "csh",
    "ksh",
    "zsh",
    "cp",
    "mv",
    "tar",
    "find",
    "vim",
    "vi",
    "nano",
    "less",
    "more",
    "python",
    "python3",
    "perl",
    "ruby",
    "nmap",
    "pkexec",
    "mount",
    "umount",
    "chsh",
    "chfn",
    "newgrp",
    "at",
    "screen",
    "tmux",
}

SUID_DIRS = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
]

CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
]


def run(probe: SystemProbe) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(_sensitive_files(probe))
    findings.append(_system_dirs(probe))
    findings.append(_home_dirs(probe))
    findings.append(_suid(probe))
    return findings


def _sensitive_files(probe: SystemProbe) -> Finding:
    problems: list[str] = []
    checked = 0
    for rel in CRITICAL_FILES:
        info = probe.info(rel, follow=True)
        if info is None:
            continue
        checked += 1
        if info.other_write:
            problems.append(f"{rel} 全局可写（{info.perm_text}）")
        elif info.other_read_owner and rel in {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}:
            problems.append(f"{rel} 可被其他用户读取（{info.perm_text}）")
        elif info.group_write:
            problems.append(f"{rel} 组可写（{info.perm_text}）")
    if not checked:
        return skip("perms.sensitive_files", CATEGORY, "敏感文件权限检查", "未找到待检查的文件。")
    if problems:
        return fail(
            "perms.sensitive_files",
            CATEGORY,
            Severity.HIGH,
            "敏感文件权限过宽",
            "账户或权限文件可被非特权用户改写或读取。",
            "修正权限，例如 chmod 644 /etc/passwd、chmod 640 /etc/shadow、chmod 440 /etc/sudoers。",
            "; ".join(problems),
        )
    return ok("perms.sensitive_files", CATEGORY, "敏感文件权限正常")


def _system_dirs(probe: SystemProbe) -> Finding:
    problems: list[str] = []
    for rel in ["/etc", "/bin", "/sbin", "/boot", "/usr/bin", "/usr/sbin", "/usr/lib"]:
        info = probe.info(rel, follow=True)
        if info is None or not info.is_dir:
            continue
        if info.other_write:
            problems.append(f"{rel}（{info.perm_text}）")
    if problems:
        return fail(
            "perms.system_dirs",
            CATEGORY,
            Severity.CRITICAL,
            "系统目录可被任意用户写入",
            "全局可写的系统目录可被用于植入恶意文件或劫持程序。",
            "立即移除 other-write 位并排查目录内容。",
            ", ".join(problems),
        )
    return ok("perms.system_dirs", CATEGORY, "系统目录不可全局写入")


def _home_dirs(probe: SystemProbe) -> Finding:
    problems: list[str] = []
    for entry in probe.glob("/home/*"):
        info = probe.info(entry, follow=True)
        if info is None or not info.is_dir:
            continue
        if info.other_write:
            problems.append(f"{entry}（{info.perm_text}）")
    if problems:
        return fail(
            "perms.home_dirs",
            CATEGORY,
            Severity.MEDIUM,
            "家目录可被任意用户写入",
            "全局可写的家目录存在被植入配置或公钥的风险。",
            "执行 chmod 750 或 700 收紧家目录权限。",
            ", ".join(problems),
        )
    return ok("perms.home_dirs", CATEGORY, "家目录不可全局写入")


def _suid(probe: SystemProbe) -> Finding:
    found: list[str] = []
    risky: list[str] = []
    for directory in SUID_DIRS:
        for entry in probe.glob(f"{directory}/*"):
            info = probe.info(entry, follow=True)
            if info is None or info.is_symlink or info.is_dir:
                continue
            if info.mode & 0o6000:
                label = f"{entry}（{info.perm_text}）"
                found.append(label)
                if entry.rsplit("/", 1)[-1] in RISKY_SUID:
                    risky.append(label)
    if risky:
        return fail(
            "perms.suid",
            CATEGORY,
            Severity.HIGH,
            "存在高风险的 SUID/SGID 程序",
            "这些程序带 SUID/SGID，可能被用于提权。",
            "确认其确有必要，否则移除 SUID/SGID 位。",
            ", ".join(risky),
        )
    if found:
        return ok(
            "perms.suid",
            CATEGORY,
            "存在 SUID/SGID 程序（待确认）",
            "共 " + str(len(found)) + " 个：" + ", ".join(found),
        )
    return ok("perms.suid", CATEGORY, "未发现 SUID/SGID 程序")
