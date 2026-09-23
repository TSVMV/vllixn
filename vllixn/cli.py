"""Command line entry point for the vllixn checkup."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .checks import run_all
from .compare import diff_baseline
from .model import Report
from .probe import SystemProbe
from .report import render_html, render_json, render_terminal
from .score import grade_for, score_findings

__all__ = ["build_report", "main"]


def build_report(probe: SystemProbe) -> Report:
    """Run every check and assemble a scored report."""
    findings = run_all(probe)
    report = Report(
        host=probe.hostname(),
        findings=findings,
        kernel=probe.kernel(),
        distro=probe.distro(),
        is_root=probe.is_root,
    )
    report.score = score_findings(findings)
    report.grade = grade_for(report.score)
    return report


def _export(path_text: str, content: str, label: str) -> int:
    path = Path(path_text)
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print(f"错误：无法写入 {label} 文件 {path}：{exc}", file=sys.stderr)
        return 2
    print(f"{label} 报告已写入 {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vllixn",
        description="只读 Linux 主机安全体检：账户、SSH、文件权限、网络、服务、内核、补丁与审计。",
    )
    parser.add_argument(
        "--root",
        default="/",
        metavar="DIR",
        help="检查目标的根目录（默认本机 /，可指向挂载的镜像目录做离线分析）",
    )
    parser.add_argument("--html", metavar="PATH", help="将报告导出为自包含 HTML 文件")
    parser.add_argument("--json", metavar="PATH", help="将报告导出为 JSON 文件")
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="ID",
        help="忽略指定检查项 ID（可重复传入，如 --ignore ssh.x11_forwarding）",
    )
    parser.add_argument(
        "--baseline",
        metavar="JSON",
        help="与此前导出的 JSON 报告对比，输出新增、已修复与仍未解决的问题",
    )
    parser.add_argument("--version", action="version", version=f"vllixn {__version__}")
    args = parser.parse_args(argv)

    probe = SystemProbe(args.root)
    report = build_report(probe)

    if args.ignore:
        ignore_set = set(args.ignore)
        report.ignored = [item.id for item in report.findings if item.id in ignore_set]
        report.findings = [item for item in report.findings if item.id not in ignore_set]
        report.score = score_findings(report.findings)
        report.grade = grade_for(report.score)

    if args.baseline:
        try:
            previous = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"错误：无法读取基线文件 {args.baseline}：{exc}", file=sys.stderr)
            return 2
        if not isinstance(previous, dict):
            print(f"错误：基线文件 {args.baseline} 格式不正确。", file=sys.stderr)
            return 2
        report.baseline = diff_baseline(report, previous)

    print(render_terminal(report))

    status = 0
    if args.html:
        status = _export(args.html, render_html(report), "HTML") or status
    if args.json:
        payload = json.dumps(render_json(report), ensure_ascii=False, indent=2)
        status = _export(args.json, payload + "\n", "JSON") or status
    return status


if __name__ == "__main__":
    raise SystemExit(main())
