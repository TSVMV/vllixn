"""Self-contained HTML report rendering (no JavaScript, no external assets)."""

from __future__ import annotations

import html
import math

from ..model import SEVERITY_LABEL, SEVERITY_ORDER, Report, Severity, Status
from ..score import category_scores

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#d97706",
    Severity.MEDIUM: "#a16207",
    Severity.LOW: "#475569",
    Severity.INFO: "#64748b",
}

STATUS_COLOR: dict[Status, str] = {
    Status.PASS: "#166534",
    Status.FAIL: "#b3261e",
    Status.SKIP: "#64748b",
}

STATUS_TEXT: dict[Status, str] = {
    Status.PASS: "通过",
    Status.FAIL: "未通过",
    Status.SKIP: "跳过",
}

STYLE = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: #f4f5f7; color: #1f2430;
       font-family: "PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif;
       font-size: 15px; line-height: 1.65; }
.wrap { max-width: 980px; margin: 0 auto; padding: 32px 20px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 28px 0 10px; border-left: 4px solid #2f5f8f;
     padding-left: 10px; }
.muted { color: #6b7280; }
.card { background: #ffffff; border: 1px solid #e3e6ea; border-radius: 10px;
        padding: 20px 24px; }
.head { display: flex; flex-wrap: wrap; gap: 24px; align-items: center; }
.meta { flex: 1 1 320px; }
.meta p { margin: 3px 0; }
.meta .label { color: #6b7280; display: inline-block; min-width: 5.5em; }
table { width: 100%; border-collapse: collapse; background: #ffffff; }
th, td { text-align: left; vertical-align: top; padding: 10px 12px;
         border-bottom: 1px solid #eceef1; }
th { font-weight: 600; color: #4b5563; background: #f8f9fb;
     border-bottom: 2px solid #e3e6ea; font-size: 13px; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 1px 9px; border-radius: 999px;
         color: #ffffff; font-size: 12px; white-space: nowrap; }
.badge.outline { background: transparent; color: #64748b; border: 1px solid #cbd2d9; }
.radar-card { text-align: center; }
.radar-card svg { display: inline-block; }
.stat { display: inline-block; margin-right: 18px; }
.stat b { font-size: 18px; }
.title-cell b { display: block; }
.title-cell .detail { color: #374151; }
.hint { color: #6b7280; }
.footer { margin-top: 26px; color: #9aa1a9; font-size: 12px; }
"""


def render(report: Report) -> str:
    """Render the full report as a standalone HTML document."""
    counts = report.counts()
    parts = "".join(
        _stat_badge(f"{SEVERITY_LABEL[s]} {counts[s]}", SEVERITY_COLOR[s])
        for s in SEVERITY_ORDER
        if counts[s]
    )
    stat_line = (
        f'<span class="stat"><b>{len(report.passed)}</b> 通过</span>'
        f'<span class="stat"><b>{len(report.failed)}</b> 未通过</span>'
        f'<span class="stat"><b>{len(report.skipped)}</b> 跳过</span>'
    )
    radar = _radar_svg(category_scores(report.findings))
    ignored_note = (
        f"<p class='hint'>已按 --ignore 跳过 {len(report.ignored)} 项：{esc(', '.join(report.ignored))}</p>"
        if report.ignored
        else ""
    )
    baseline_section = _baseline_section(report.baseline)
    sections = []
    for category in report.categories():
        rows = "".join(_row(item) for item in report.findings if item.category == category)
        sections.append(
            f"<h2>{esc(category)}</h2>"
            "<table><thead><tr><th style='width:6em'>状态</th>"
            "<th style='width:4.5em'>级别</th><th>检查项</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    return (
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>vllixn 体检报告 - {esc(report.host)}</title>"
        f"<style>{STYLE}</style></head><body><div class='wrap'>"
        f"<h1>vllixn Linux 安全体检报告</h1>"
        "<p class='muted'>只读检查，报告不包含可执行内容</p>"
        "<div class='card head'>"
        f"{_score_svg(report.score)}"
        "<div class='meta'>"
        f"<p><span class='label'>主机</span>{esc(report.host)}</p>"
        f"<p><span class='label'>系统</span>{esc(report.distro)}（内核 {esc(report.kernel)}）</p>"
        f"<p><span class='label'>时间</span>{_time_text(report)}</p>"
        f"<p><span class='label'>权限</span>{'root，完整检查' if report.is_root else '非 root，部分检查跳过'}</p>"
        f"<p><span class='label'>等级</span><b>{esc(report.grade)}</b>（{report.score}/100）</p>"
        "</div></div>"
        f"<p style='margin:18px 0 4px'>{stat_line}</p>"
        f"<p class='hint'>未通过按级别：{parts if parts else '无'}</p>"
        f"{ignored_note}"
        f"<h2>分类得分</h2>"
        f"<div class='card radar-card'>{radar}"
        "<p class='hint'>各分类独立按 0-100 打分，跳过的检查项不计入。</p></div>"
        + baseline_section
        + "".join(sections)
        + "<p class='footer'>由 vllixn 生成，数据来自只读探测本机配置。</p>"
        "</div></body></html>"
    )


def _row(item) -> str:
    if item.status is Status.FAIL:
        level = (
            f"<span class='badge' style='background:{SEVERITY_COLOR[item.severity]}'>"
            f"{SEVERITY_LABEL[item.severity]}</span>"
        )
    elif item.status is Status.SKIP:
        level = "<span class='badge outline'>-</span>"
    else:
        level = "<span class='badge outline'>-</span>"
    detail = f"<span class='detail'>{esc(item.detail)}</span>" if item.detail else ""
    advice = f"<br><span class='hint'>建议：{esc(item.advice)}</span>" if item.advice else ""
    evidence = f"<br><span class='hint'>证据：{esc(item.evidence)}</span>" if item.evidence else ""
    note = detail + advice + evidence
    return (
        f"<tr><td><span class='badge' style='background:{STATUS_COLOR[item.status]}'>"
        f"{STATUS_TEXT[item.status]}</span></td>"
        f"<td>{level}</td>"
        f"<td class='title-cell'><b>{esc(item.title)}</b>{note}</td></tr>"
    )


def _stat_badge(text: str, color: str) -> str:
    return f"<span class='badge' style='background:{color}'>{esc(text)}</span>"


def _score_svg(score: int) -> str:
    radius = 52
    circumference = 2 * math.pi * radius
    filled = circumference * score / 100
    color = "#166534" if score >= 75 else "#a16207" if score >= 60 else "#b3261e"
    return (
        "<svg width='140' height='140' viewBox='0 0 140 140' role='img' "
        f"aria-label='评分 {score}'>"
        "<circle cx='70' cy='70' r='52' fill='none' stroke='#e8eaee' stroke-width='14'/>"
        f"<circle cx='70' cy='70' r='52' fill='none' stroke='{color}' stroke-width='14' "
        "stroke-linecap='round' "
        f"stroke-dasharray='{filled:.1f} {circumference:.1f}' "
        "transform='rotate(-90 70 70)'/>"
        f"<text x='70' y='66' text-anchor='middle' font-size='30' fill='#1f2430'>{score}</text>"
        "<text x='70' y='90' text-anchor='middle' font-size='13' fill='#6b7280'>总分</text>"
        "</svg>"
    )


def _time_text(report: Report) -> str:
    return esc(report.generated_at.astimezone().strftime("%Y-%m-%d %H:%M:%S"))


def esc(value: str) -> str:
    return html.escape(str(value), quote=True)


def _radar_svg(scores: list[tuple[str, int]]) -> str:
    """Draw an SVG radar chart of per-category scores."""
    if not scores:
        return "<p class='hint'>暂无分类数据</p>"
    cx, cy, radius = 110, 110, 80
    labels = [name for name, _ in scores]
    values = [score for _, score in scores]
    n = len(scores)
    def angle(i: int) -> float:
        return math.radians(-90 + 360 * i / n)

    def vertex(i: int, value: int) -> tuple[float, float]:
        r = radius * value / 100
        return cx + r * math.cos(angle(i)), cy + r * math.sin(angle(i))

    grid = ""
    for level in (25, 50, 75, 100):
        points = " ".join(
            f"{cx + radius * level / 100 * math.cos(angle(i)):.1f},"
            f"{cy + radius * level / 100 * math.sin(angle(i)):.1f}"
            for i in range(n)
        )
        grid += f"<polygon points='{points}' fill='none' stroke='#e8eaee' stroke-width='1'/>"

    spokes = "".join(
        f"<line x1='{cx}' y1='{cy}' x2='{cx + radius * math.cos(angle(i)):.1f}' "
        f"y2='{cy + radius * math.sin(angle(i)):.1f}' stroke='#eceef1' stroke-width='1'/>"
        for i in range(n)
    )

    data_points = " ".join(
        f"{vertex(i, values[i])[0]:.1f},{vertex(i, values[i])[1]:.1f}" for i in range(n)
    )

    label_xml = ""
    for i, label in enumerate(labels):
        lx = cx + (radius + 22) * math.cos(angle(i))
        ly = cy + (radius + 22) * math.sin(angle(i))
        anchor = "start" if lx > cx + 4 else "end" if lx < cx - 4 else "middle"
        label_xml += (
            f"<text x='{lx:.1f}' y='{ly:.1f}' text-anchor='{anchor}' "
            f"dominant-baseline='middle' font-size='12' fill='#475569'>"
            f"{esc(label)} {values[i]}</text>"
        )

    return (
        "<svg width='220' height='220' viewBox='0 0 220 220' role='img' "
        "aria-label='分类得分雷达图'>"
        f"{grid}{spokes}"
        f"<polygon points='{data_points}' fill='rgba(47,95,143,0.22)' "
        "stroke='#2f5f8f' stroke-width='2'/>"
        f"{''.join(f'<circle cx={vertex(i, values[i])[0]:.1f} cy={vertex(i, values[i])[1]:.1f} r=3 fill=#2f5f8f />' for i in range(n))}"
        f"{label_xml}"
        "</svg>"
    )


def _baseline_section(baseline: dict | None) -> str:
    if baseline is None:
        return ""
    new_items = baseline.get("new") or []
    fixed = baseline.get("fixed") or []
    still_open = baseline.get("still_open") or []
    generated = esc(str(baseline.get("generated_at") or "未知时间"))

    def rows(items: list[dict]) -> str:
        return "".join(
            "<tr>"
            f"<td><span class='badge outline'>{esc(str(item.get('id', '')))}</span></td>"
            f"<td>{esc(str(item.get('category', '')))}</td>"
            f"<td>{esc(str(item.get('title', '')))}</td>"
            "</tr>"
            for item in items
        )

    return (
        "<h2>与基线对比</h2>"
        f"<p class='hint'>基线生成于 {generated}</p>"
        "<table><thead><tr><th>检查项 ID</th><th style='width:6em'>分类</th>"
        "<th>说明</th></tr></thead><tbody>"
        f"<tr><td colspan='3' class='hint'>新增问题 {len(new_items)} 项</td></tr>{rows(new_items)}"
        f"<tr><td colspan='3' class='hint'>已修复 {len(fixed)} 项</td></tr>{rows(fixed)}"
        f"<tr><td colspan='3' class='hint'>仍未解决 {len(still_open)} 项</td></tr>{rows(still_open)}"
        "</tbody></table>"
    )
