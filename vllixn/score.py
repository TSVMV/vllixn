"""Turn a list of findings into a 0-100 score and a grade."""

from __future__ import annotations

from .model import SEVERITY_WEIGHT, Finding

__all__ = ["grade_for", "score_findings"]

GRADES: list[tuple[int, str]] = [
    (90, "优秀"),
    (75, "良好"),
    (60, "一般"),
    (40, "较差"),
    (0, "危险"),
]


def score_findings(findings: list[Finding]) -> int:
    """Subtract a weight per failed finding, floored at zero."""
    penalty = 0
    for item in findings:
        if item.failed:
            penalty += SEVERITY_WEIGHT.get(item.severity, 0)
    return max(0, 100 - penalty)


def category_scores(findings: list[Finding]) -> list[tuple[str, int]]:
    """Per-category 0-100 score, keeping the order categories were checked in."""
    penalties: dict[str, int] = {}
    order: list[str] = []
    for item in findings:
        if item.category not in penalties:
            penalties[item.category] = 0
            order.append(item.category)
        if item.failed:
            penalties[item.category] += SEVERITY_WEIGHT.get(item.severity, 0)
    return [(category, max(0, 100 - penalties[category])) for category in order]


def grade_for(score: int) -> str:
    """Map a numeric score to a Chinese grade label."""
    for threshold, label in GRADES:
        if score >= threshold:
            return label
    return GRADES[-1][1]
