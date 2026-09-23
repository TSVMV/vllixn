"""Core data model for a checkup: statuses, findings and the report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

__all__ = [
    "Finding",
    "Report",
    "Severity",
    "Status",
    "fail",
    "ok",
    "skip",
]


class Severity(str, Enum):
    """Risk level of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    """Outcome of a single check."""

    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


# Risk weight used to compute the score. Only FAIL findings are deducted.
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "严重",
    Severity.HIGH: "高",
    Severity.MEDIUM: "中",
    Severity.LOW: "低",
    Severity.INFO: "提示",
}

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    """One check result.

    A finding always describes a single rule against the current host. ``status``
    says whether the rule passed, failed, or could not be evaluated. ``severity``
    is the risk the rule carries when it fails.
    """

    id: str
    category: str
    title: str
    status: Status
    severity: Severity = Severity.INFO
    detail: str = ""
    advice: str = ""
    evidence: str = ""

    @property
    def failed(self) -> bool:
        return self.status is Status.FAIL

    @property
    def skipped(self) -> bool:
        return self.status is Status.SKIP


def fail(
    id: str,
    category: str,
    severity: Severity,
    title: str,
    detail: str,
    advice: str = "",
    evidence: str = "",
) -> Finding:
    """Build a failing finding."""
    return Finding(id, category, title, Status.FAIL, severity, detail, advice, evidence)


def ok(id: str, category: str, title: str, detail: str = "") -> Finding:
    """Build a passing finding."""
    return Finding(id, category, title, Status.PASS, Severity.INFO, detail)


def skip(id: str, category: str, title: str, detail: str = "") -> Finding:
    """Build a finding that could not be evaluated."""
    return Finding(id, category, title, Status.SKIP, Severity.INFO, detail)


@dataclass
class Report:
    """A full checkup result for one host."""

    host: str
    findings: list[Finding]
    kernel: str = ""
    distro: str = ""
    is_root: bool = False
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    score: int = 100
    grade: str = ""
    ignored: list[str] = field(default_factory=list)
    baseline: dict | None = None

    @property
    def failed(self) -> list[Finding]:
        return [item for item in self.findings if item.failed]

    @property
    def skipped(self) -> list[Finding]:
        return [item for item in self.findings if item.skipped]

    @property
    def passed(self) -> list[Finding]:
        return [item for item in self.findings if item.status is Status.PASS]

    def counts(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for item in self.findings:
            if item.failed:
                counts[item.severity] += 1
        return counts

    def categories(self) -> list[str]:
        seen: list[str] = []
        for item in self.findings:
            if item.category not in seen:
                seen.append(item.category)
        return seen
