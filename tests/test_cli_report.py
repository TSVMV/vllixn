"""Tests for scoring, report rendering and the CLI entry point."""

from __future__ import annotations

import json

from conftest import make_probe, write

from vllixn.cli import build_report, main
from vllixn.model import Finding, Severity, Status, fail, ok
from vllixn.report import render_html, render_json, render_terminal
from vllixn.score import grade_for, score_findings

PASSWD = "\n".join(
    [
        "root:x:0:0:root:/root:/bin/bash",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
    ]
)


def test_score_subtracts_weights():
    findings = [
        ok("a", "c", "t"),
        fail("b", "c", Severity.HIGH, "t", "d"),
        fail("c", "c", Severity.LOW, "t", "d"),
    ]
    assert score_findings(findings) == 100 - 12 - 2


def test_score_floored_at_zero():
    findings = [fail(f"i{i}", "c", Severity.CRITICAL, "t", "d") for i in range(5)]
    assert score_findings(findings) == 0


def test_grades():
    assert grade_for(95) == "优秀"
    assert grade_for(80) == "良好"
    assert grade_for(65) == "一般"
    assert grade_for(45) == "较差"
    assert grade_for(10) == "危险"


def test_terminal_report_sections():
    report = build_report(make_probe(_fixture_root()))
    text = render_terminal(report)
    assert "vllixn Linux 安全体检报告" in text
    assert "未通过项" in text
    assert "通过项" in text
    assert "总分:" in text


def test_html_report_is_self_contained_and_escaped():
    report = build_report(make_probe(_fixture_root()))
    html = render_html(report)
    assert "<script" not in html.lower()
    assert "svg" in html.lower()
    assert html.startswith("<!DOCTYPE html>")


def test_json_report_shape():
    report = build_report(make_probe(_fixture_root()))
    data = render_json(report)
    assert data["tool"] == "vllixn"
    assert data["score"] == report.score
    assert len(data["findings"]) == len(report.findings)
    assert set(data["summary"]) == {"total", "passed", "failed", "skipped"}


def test_cli_exports_html_and_json(tmp_path):
    root = _fixture_root()
    html_path = tmp_path / "report.html"
    json_path = tmp_path / "report.json"
    code = main(["--root", str(root), "--html", str(html_path), "--json", str(json_path)])
    assert code == 0
    assert html_path.exists()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["findings"]


def test_cli_export_write_failure_returns_error(tmp_path):
    code = main(["--root", str(_fixture_root()), "--html", str(tmp_path / "no-dir" / "x.html")])
    assert code == 2


def test_failed_finding_fields_survive_json_roundtrip():
    finding = Finding(
        id="x",
        category="c",
        title="t<",
        status=Status.FAIL,
        severity=Severity.HIGH,
        detail="d",
        advice="a",
        evidence="e&",
    )
    report = build_report(make_probe(_fixture_root()))
    report.findings.insert(0, finding)
    data = json.loads(json.dumps(render_json(report), ensure_ascii=False))
    assert data["findings"][0]["title"] == "t<"
    assert data["findings"][0]["evidence"] == "e&"


def _fixture_root():
    import tempfile
    from pathlib import Path

    tmp = Path(tempfile.mkdtemp())
    write(tmp, "/etc/passwd", PASSWD + "\n")
    write(tmp, "/etc/shadow", "root:$6$h:1:0:99:7:::\n", mode=0o640)
    write(tmp, "/etc/ssh/sshd_config", "PasswordAuthentication no\nPermitRootLogin no\n")
    write(tmp, "/proc/sys/kernel/randomize_va_space", "2\n")
    write(tmp, "/proc/sys/kernel/hostname", "test-host\n")
    write(tmp, "/proc/sys/kernel/osrelease", "6.8.0-test\n")
    write(tmp, "/etc/os-release", 'PRETTY_NAME="Test Linux 1.0"\n')
    write(tmp, "/etc/login.defs", "PASS_MAX_DAYS 90\nUMASK 022\n")
    return tmp


def test_category_scores_deducts_per_category():
    from vllixn.score import category_scores
    findings = [
        ok("a", "账户", "t"),
        fail("b", "账户", Severity.HIGH, "t", "d"),
        fail("c", "SSH", Severity.LOW, "t", "d"),
    ]
    scores = dict(category_scores(findings))
    assert scores["账户"] == 88
    assert scores["SSH"] == 98


def test_ignore_removes_findings(tmp_path):
    root = _fixture_root()
    ignored = "accounts.default_umask"
    code = main(["--root", str(root), "--ignore", ignored, "--json", str(tmp_path / "x.json")])
    assert code == 0
    data = json.loads((tmp_path / "x.json").read_text(encoding="utf-8"))
    assert ignored in data["ignored"]
    assert all(f["id"] != ignored for f in data["findings"])


def test_baseline_diff_reports_fixed_and_new(tmp_path):
    import json
    prev = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "score": 50,
        "findings": [
            {"id": "a", "title": "old fail", "category": "c", "status": "fail"},
            {"id": "b", "title": "still fail", "category": "c", "status": "fail"},
        ],
    }
    baseline_path = tmp_path / "prev.json"
    baseline_path.write_text(json.dumps(prev), encoding="utf-8")
    root = _fixture_root()
    out = tmp_path / "cur.json"
    code = main(["--root", str(root), "--baseline", str(baseline_path), "--json", str(out)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    baseline = data["baseline"]
    fixed_ids = {item["id"] for item in baseline["fixed"]}
    assert "a" in fixed_ids
    assert all(item["id"] == "b" for item in baseline["still_open"])


def test_terminal_baseline_block_renders(tmp_path):
    import json
    prev = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "score": 50,
        "findings": [{"id": "zzz", "title": "gone", "category": "c", "status": "fail"}],
    }
    baseline_path = tmp_path / "prev.json"
    baseline_path.write_text(json.dumps(prev), encoding="utf-8")
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["--root", str(_fixture_root()), "--baseline", str(baseline_path)])
    out = buf.getvalue()
    assert "与基线对比" in out
    assert "已修复" in out


def test_html_renders_radar_and_baseline(tmp_path):
    import json
    prev = {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "score": 50,
        "findings": [{"id": "zzz", "title": "gone", "category": "c", "status": "fail"}],
    }
    baseline_path = tmp_path / "prev.json"
    baseline_path.write_text(json.dumps(prev), encoding="utf-8")
    html_path = tmp_path / "r.html"
    main(["--root", str(_fixture_root()), "--baseline", str(baseline_path), "--html", str(html_path)])
    text = html_path.read_text(encoding="utf-8")
    assert "radar" in text.lower()
    assert "与基线对比" in text
    assert "<script" not in text.lower()
