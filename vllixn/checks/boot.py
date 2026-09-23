"""Boot loader, kernel module blacklist and core dump checks."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "启动"

GRUB_CONFIGS = [
    "/boot/grub/grub.cfg",
    "/boot/grub2/grub.cfg",
    "/boot/grub2/grubenv",
]

# Network filesystems and legacy protocols commonly blacklisted per CIS.
RISKY_MODULES = [
    "usb-storage",
    "firewire-core",
    "dccp",
    "sctp",
    "rds",
    "tipc",
]

COREDUMP_CONF = "/etc/systemd/coredump.conf"


def run(probe: SystemProbe) -> list[Finding]:
    return [_grub_perms(probe), _module_blacklist(probe), _core_dump(probe)]


def _grub_perms(probe: SystemProbe) -> Finding:
    problems: list[str] = []
    checked = False
    for rel in GRUB_CONFIGS + probe.glob("/boot/efi/EFI/*/grub.cfg"):
        info = probe.info(rel, follow=False)
        if info is None:
            continue
        checked = True
        if info.any_write():
            problems.append(f"{rel}（{info.perm_text}）")
    if not checked:
        return skip(
            "boot.grub_perms",
            CATEGORY,
            "引导配置权限检查",
            "未找到 GRUB 配置文件（可能使用其他引导器）。",
        )
    if problems:
        return fail(
            "boot.grub_perms",
            CATEGORY,
            Severity.HIGH,
            "GRUB 配置可被他人写入",
            "引导配置可写意味着攻击者可注入内核参数（如 init=/bin/bash）直接获取 root。",
            "执行 chmod 600 并确认属主为 root:root。",
            ", ".join(problems),
        )
    return ok("boot.grub_perms", CATEGORY, "GRUB 配置权限正常")


def _module_blacklist(probe: SystemProbe) -> Finding:
    blacklisted: set[str] = set()
    for conf in probe.glob("/etc/modprobe.d/*.conf"):
        for line in probe.read_lines(conf):
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 2 and parts[0] == "blacklist":
                blacklisted.add(parts[1])
    missing = [name for name in RISKY_MODULES if name not in blacklisted]
    if len(missing) == len(RISKY_MODULES):
        return fail(
            "boot.module_blacklist",
            CATEGORY,
            Severity.LOW,
            "常见高危内核模块未列入黑名单",
            "usb-storage、SCTP/DCCP/RDS/TIPC 等模块暴露面大且多数主机用不到。",
            "在 /etc/modprobe.d/ 下创建黑名单配置（blacklist <模块名>），按需保留。",
        )
    if missing:
        return ok(
            "boot.module_blacklist",
            CATEGORY,
            "部分高危模块已黑名单",
            "未覆盖：" + ", ".join(missing),
        )
    return ok("boot.module_blacklist", CATEGORY, "常见高危模块均已黑名单")


def _core_dump(probe: SystemProbe) -> Finding:
    limits = probe.glob("/etc/security/limits.conf") + probe.glob("/etc/security/limits.d/*.conf")
    for conf in limits:
        for line in probe.read_lines(conf):
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 4 and parts[1] == "hard" and parts[2] == "core" and parts[3] == "0":
                return ok("boot.core_dump", CATEGORY, "core dump 已禁用", conf)
    conf_text = probe.read_text(COREDUMP_CONF, "")
    in_section = False
    for line in conf_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped.lower() == "[coredump]"
            continue
        if in_section and "=" in stripped:
            key, value = (part.strip().lower() for part in stripped.split("=", 1))
            if key == "storage" and value == "none":
                return ok("boot.core_dump", CATEGORY, "core dump 已禁用", COREDUMP_CONF)
            if key == "processsizemax" and value == "0":
                return ok("boot.core_dump", CATEGORY, "core dump 已禁用", COREDUMP_CONF)
    return fail(
        "boot.core_dump",
        CATEGORY,
        Severity.LOW,
        "core dump 未禁用",
        "进程崩溃时的内存转储可能包含口令与密钥，且占用磁盘空间。",
        "在 limits.conf 设置 * hard core 0，或在 coredump.conf 设置 Storage=none。",
    )
