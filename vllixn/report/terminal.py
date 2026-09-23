"""Plain-text terminal report rendering."""

from __future__ import annotations

from ..model import SEVERITY_LABEL, SEVERITY_ORDER, Report, Status
from ..score import category_scores

BAR = "-" * 64
HEAVY = "=" * 64
STATUS_MARK: dict[Status, str] = {
    Status.PASS: "+",
    Status.FAIL: "!",
    Status.SKIP: "-",
}


def render(report: Report) -> str:
    """Render the report as a terminal-friendly Chinese text block."""
    lines: list[str] = []
    lines.append(HEAVY)
    lines.append("vllixn Linux 安全体检报告")
    lines.append(HEAVY)
    lines.append(f"主机: {report.host}")
    lines.append(f"系统: {report.distro}    内核: {report.kernel}")
    lines.append(f"时间: {_format_time(report)}")
    if report.is_root:
        lines.append("权限: root（完整检查）")
    else:
        lines.append("权限: 非 root（部分检查将跳过）")
    lines.append("")
    lines.append(f"总分: {report.score}/100    等级: {report.grade}")
    lines.append(
        f"检查项: 共 {len(report.findings)} 项    "
        f"通过 {len(report.passed)}    未通过 {len(report.failed)}    跳过 {len(report.skipped)}"
    )
    counts = report.counts()
    parts = [f"{SEVERITY_LABEL[s]} {counts[s]}" for s in SEVERITY_ORDER if counts[s]]
    lines.append("未通过按级别: " + (" | ".join(parts) if parts else "无"))
    cat_line = " | ".join(f"{name} {score}" for name, score in category_scores(report.findings))
    if cat_line:
        lines.append(f"分类得分: {cat_line}")
    if report.ignored:
        lines.append(f"已忽略 {len(report.ignored)} 项: {', '.join(report.ignored)}")
    lines.append("")

    if report.failed:
        lines.append(BAR)
        lines.append("未通过项（按严重程度排列）")
        lines.append(BAR)
        ordered = sorted(report.failed, key=lambda item: item.severity.value)
        for item in ordered:
            lines.append(f"[{SEVERITY_LABEL[item.severity]}] {item.category} / {item.title}")
            if item.detail:
                lines.append(f"    说明: {item.detail}")
            if item.advice:
                lines.append(f"    建议: {item.advice}")
            if item.evidence:
                lines.append(f"    证据: {item.evidence}")
            lines.append("")

    if report.skipped:
        lines.append(BAR)
        lines.append("跳过项")
        lines.append(BAR)
        for item in report.skipped:
            suffix = f": {item.detail}" if item.detail else ""
            lines.append(f"- {item.category} / {item.title}{suffix}")
        lines.append("")

    lines.append(BAR)
    lines.append(f"通过项（{len(report.passed)}）")
    lines.append(BAR)
    for item in report.passed:
        suffix = f" — {item.detail}" if item.detail else ""
        lines.append(f"+ [{item.category}] {item.title}{suffix}")
    lines.append("")

    if report.baseline is not None:
        lines.extend(_baseline_block(report.baseline))

    lines.append("本报告由 vllixn 只读体检生成，未修改任何系统配置。")
    return "\n".join(lines)


def _baseline_block(baseline: dict) -> list[str]:
    lines = [BAR, "与基线对比", BAR]
    generated = baseline.get("generated_at") or "未知时间"
    previous_score = baseline.get("previous_score")
    header = f"基线生成于 {generated}"
    if previous_score is not None:
        header += f"（基线总分 {previous_score}）"
    lines.append(header)
    new_items = baseline.get("new") or []
    fixed = baseline.get("fixed") or []
    still_open = baseline.get("still_open") or []
    lines.append(f"  新增问题 {len(new_items)} 项：")
    for item in new_items:
        lines.append(f"    - [{item.get('category', '')}] {item.get('title', '')}（{item.get('id')}）")
    lines.append(f"  已修复 {len(fixed)} 项：")
    for item in fixed:
        lines.append(f"    - [{item.get('category', '')}] {item.get('title', '')}（{item.get('id')}）")
    lines.append(f"  仍未解决 {len(still_open)} 项")
    lines.append("")
    return lines


def _format_time(report: Report) -> str:
    local = report.generated_at.astimezone()
    return local.strftime("%Y-%m-%d %H:%M:%S %z").rstrip()
