"""Diff two checkup exports: what got fixed, what appeared, what persists."""

from __future__ import annotations

from .model import Report

__all__ = ["diff_baseline"]


def diff_baseline(current: Report, previous: dict) -> dict:
    """Compare the current report against a previous JSON export.

    A check that no longer fails counts as fixed even when it disappeared
    (e.g. the service was removed entirely).
    """
    prev: dict[str, dict] = {
        str(item.get("id")): item for item in previous.get("findings", []) if item.get("id")
    }
    curr: dict[str, object] = {item.id: item for item in current.findings}

    def prev_failed(fid: str) -> bool:
        entry = prev.get(fid)
        return bool(entry) and entry.get("status") == "fail"

    def curr_failed(fid: str) -> bool:
        item = curr.get(fid)
        return bool(item) and getattr(item, "failed", False)

    new_issues = [
        {"id": fid, "title": getattr(curr[fid], "title", ""), "category": getattr(curr[fid], "category", "")}
        for fid in curr
        if curr_failed(fid) and not prev_failed(fid)
    ]
    fixed = [
        {"id": fid, "title": prev[fid].get("title", ""), "category": prev[fid].get("category", "")}
        for fid in prev
        if prev_failed(fid) and (fid not in curr or not curr_failed(fid))
    ]
    still_open = [
        {"id": fid, "title": getattr(curr[fid], "title", ""), "category": getattr(curr[fid], "category", "")}
        for fid in curr
        if curr_failed(fid) and prev_failed(fid)
    ]
    return {
        "generated_at": str(previous.get("generated_at", "")),
        "previous_score": previous.get("score"),
        "new": new_issues,
        "fixed": fixed,
        "still_open": still_open,
    }
