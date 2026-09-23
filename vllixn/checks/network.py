"""Network exposure checks: listening ports and host firewall."""

from __future__ import annotations

from ..model import Finding, Severity, fail, ok, skip
from ..probe import CommandResult, SystemProbe

CATEGORY = "网络"

# Plain-text or inherently unsafe services that must never face a network.
PLAINTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    111: "rpcbind",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    2049: "NFS",
}

# Local services that become a real risk when bound to all interfaces.
RISKY_SERVICE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5900: "VNC",
}

WILDCARD_HOSTS = {"0.0.0.0", "::", "*", "[::]"}


def run(probe: SystemProbe) -> list[Finding]:
    return [_listening(probe), _firewall(probe)]


def parse_ss(text: str) -> list[tuple[str, str]] | None:
    """Parse ``ss -tulnpH`` output into (netid, local) pairs.

    Returns None when the command produced no parsable output at all so the
    caller can distinguish "no listener" from "cannot run ss".
    """
    entries: list[tuple[str, str]] = []
    saw_line = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        saw_line = True
        parts = line.split()
        if len(parts) < 5:
            continue
        netid, local = parts[0], parts[4]
        if ":" in local:
            entries.append((netid, local))
    if not saw_line:
        return None
    return entries


def _port(local: str) -> int:
    try:
        return int(local.rsplit(":", 1)[-1])
    except ValueError:
        return 0


def _is_wildcard(local: str) -> bool:
    host = local.rsplit(":", 1)[0]
    return host in WILDCARD_HOSTS


def _listening(probe: SystemProbe) -> Finding:
    text = probe.command_text(["ss", "-tulnpH"])
    if not text.strip():
        result = probe.command(["ss", "-tulnpH"])
        if not result.ok:
            return skip(
                "network.listening",
                CATEGORY,
                "监听端口检查",
                "ss 命令不可用，无法枚举监听端口。",
            )
    entries = parse_ss(text)
    if entries is None:
        return ok("network.listening", CATEGORY, "未发现监听端口")

    external = [local for _, local in entries if _is_wildcard(local)]
    if not external:
        return ok("network.listening", CATEGORY, "未发现绑定全部地址的监听端口")

    ports = sorted({_port(local) for local in external})
    plaintext = [port for port in ports if port in PLAINTEXT_PORTS]
    risky = [port for port in ports if port in RISKY_SERVICE_PORTS]

    evidence = ", ".join(
        f"{PLAINTEXT_PORTS.get(p) or RISKY_SERVICE_PORTS.get(p) or '端口'} {p}" for p in ports
    )
    if plaintext:
        names = "、".join(PLAINTEXT_PORTS[p] for p in plaintext)
        return fail(
            "network.listening",
            CATEGORY,
            Severity.HIGH,
            "对外监听明文或不安全协议端口",
            f"以下协议以明文传输或已被弃用，暴露在全部地址上：{names}。",
            "关闭对应服务，或改用加密替代（如 SSH 替代 Telnet、SFTP 替代 FTP）。",
            evidence,
        )
    if risky:
        names = "、".join(RISKY_SERVICE_PORTS[p] for p in risky)
        return fail(
            "network.listening",
            CATEGORY,
            Severity.MEDIUM,
            "数据服务端口绑定全部地址",
            f"以下服务监听在全部地址上，建议仅监听 127.0.0.1：{names}。",
            "修改服务监听地址为 127.0.0.1，或用防火墙限制来源。",
            evidence,
        )
    return ok(
        "network.listening",
        CATEGORY,
        f"对外监听端口 {len(ports)} 个",
        "端口列表：" + ", ".join(str(p) for p in ports),
    )


# (tool name, argv, judge) -> judge returns True/False; raise nothing.
FIREWALL_CHECKS: list[tuple[str, list[str], object]] = [
    ("nftables", ["nft", "list", "ruleset"], lambda r: "chain" in r.stdout.lower()),
    ("iptables", ["iptables", "-S"], lambda r: "-A " in r.stdout),
    ("ufw", ["ufw", "status"], lambda r: "active" in r.stdout.lower()),
    ("firewalld", ["firewall-cmd", "--state"], lambda r: r.stdout.strip() == "running"),
]


def _blocked_by_permission(result: CommandResult) -> bool:
    marker = ("permission", "permitted", "操作不被允许", "权限")
    lowered = result.stderr.lower()
    return any(word in lowered for word in marker)


def _firewall(probe: SystemProbe) -> Finding:
    present = False
    judged = False
    active: list[str] = []
    for name, argv, judge in FIREWALL_CHECKS:
        result = probe.command(argv)
        if result.missing or result.code == 126:
            continue
        if not result.ok and _blocked_by_permission(result):
            present = True
            continue
        present = True
        judged = True
        if judge(result):
            active.append(name)
    if active:
        return ok(
            "network.firewall",
            CATEGORY,
            "检测到活动防火墙规则",
            "工具：" + "、".join(active),
        )
    if judged:
        return fail(
            "network.firewall",
            CATEGORY,
            Severity.MEDIUM,
            "未检测到启用的防火墙规则",
            "主机上存在防火墙管理工具，但没有查询到任何活动规则。",
            "启用 ufw/nftables/firewalld，至少放行 SSH 并按需收紧其他端口。",
        )
    if present:
        return skip(
            "network.firewall",
            CATEGORY,
            "防火墙规则检查",
            "防火墙命令需要更高权限，无法确认规则状态。",
        )
    return skip(
        "network.firewall",
        CATEGORY,
        "防火墙规则检查",
        "未找到 nft/iptables/ufw/firewall-cmd 中任何防火墙管理命令。",
    )
