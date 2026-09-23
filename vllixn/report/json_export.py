"""JSON export for machine consumption."""

from __future__ import annotations

from ..model import Report

__all__ = ["render_json"]


def render_json(report: Report) -> dict:
    """Return the report as a JSON-serializable mapping."""
    return {
        "tool": "vllixn",
        "host": report.host,
        "distro": report.distro,
        "kernel": report.kernel,
        "is_root": report.is_root,
        "generated_at": report.generated_at.isoformat(),
        "score": report.score,
        "grade": report.grade,
        "summary": {
            "total": len(report.findings),
            "passed": len(report.passed),
            "failed": len(report.failed),
            "skipped": len(report.skipped),
        },
        "ignored": report.ignored,
        "baseline": report.baseline,
        "findings": [
            {
                "id": item.id,
                "category": item.category,
                "title": item.title,
                "status": item.status.value,
                "severity": item.severity.value,
                "detail": item.detail,
                "advice": item.advice,
                "evidence": item.evidence,
            }
            for item in report.findings
        ],
    }
