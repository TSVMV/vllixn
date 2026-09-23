"""Patch freshness checks based on package manager update logs."""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..model import Finding, Severity, fail, ok, skip
from ..probe import SystemProbe

CATEGORY = "补丁"

STALE_DAYS = 60


@dataclass(frozen=True)
class Family:
    """One supported package family: marker path plus its update logs."""

    name: str
    marker: str
    logs: tuple[str, ...]

    def present(self, probe: SystemProbe) -> bool:
        return probe.exists(self.marker)


FAMILIES: tuple[Family, ...] = (
    Family("dpkg/apt", "/var/lib/dpkg/status", ("/var/log/apt/history.log*",)),
    Family("rpm/dnf", "/var/lib/rpm", ("/var/log/dnf.log*", "/var/log/yum.log*")),
)


def run(probe: SystemProbe) -> list[Finding]:
    return [_update_age(probe)]


def latest_log_mtime(probe: SystemProbe, family: Family) -> float | None:
    stamps: list[float] = []
    for pattern in family.logs:
        for log in probe.glob(pattern):
            info = probe.info(log)
            if info is not None:
                stamps.append(info.mtime)
    return max(stamps) if stamps else None


def _update_age(probe: SystemProbe) -> Finding:
    now = time.time()
    evaluated = False
    newest_name = ""
    newest_mtime = -1.0
    for family in FAMILIES:
        if not family.present(probe):
            continue
        evaluated = True
        mtime = latest_log_mtime(probe, family)
        if mtime is None:
            continue
        if mtime > newest_mtime:
            newest_mtime = mtime
            newest_name = family.name
    if not evaluated:
        return skip(
            "patches.update_age",
            CATEGORY,
            "系统更新检查",
            "未识别到 dpkg 或 rpm 包管理体系。",
        )
    if newest_mtime < 0:
        return skip(
            "patches.update_age",
            CATEGORY,
            "系统更新检查",
            "未找到包管理器的更新日志，无法判断最近一次更新时间。",
        )
    age_days = (now - newest_mtime) / 86400
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(newest_mtime))
    if age_days > STALE_DAYS:
        return fail(
            "patches.update_age",
            CATEGORY,
            Severity.MEDIUM,
            f"超过 {STALE_DAYS} 天未安装系统更新",
            f"{newest_name} 的更新日志停留在 {stamp}，安全补丁可能长期缺失。",
            "运行系统包管理器安装更新（apt upgrade 或 dnf upgrade），并保持自动安全更新开启。",
            f"最后更新时间：{stamp}（{age_days:.0f} 天前）",
        )
    return ok(
        "patches.update_age",
        CATEGORY,
        "近期有安装系统更新",
        f"{newest_name} 最后更新时间：{stamp}（{age_days:.0f} 天前）",
    )
