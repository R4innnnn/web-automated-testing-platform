from __future__ import annotations

import html
import json
from pathlib import Path


def _pretty(value) -> str:
    return html.escape(json.dumps(value, ensure_ascii=False, indent=2))


def write_reports(run_dir: Path, result: dict) -> None:
    findings = result.get("findings", [])
    rows: list[str] = []
    for index, finding in enumerate(findings, start=1):
        name = f"finding-{index:03d}.html"
        rows.append(
            "<tr><td><a href='" + name + "'>" + html.escape(finding["title"]) +
            "</a></td><td>" + html.escape(finding["module"]) +
            "</td><td>" + html.escape(finding["severity"]) +
            "</td><td>" + html.escape(finding.get("confidence", "")) +
            "</td><td>" + html.escape(finding.get("url", "")) +
            ("（已标记误报）" if finding.get("suppressed") else "") +
            "</td></tr>"
        )
        screenshot = finding.get("screenshot")
        screenshot_html = (
            f"<img src='{html.escape(screenshot, quote=True)}' alt='页面证据' "
            "style='max-width:100%;border:1px solid #ddd'>"
            if screenshot else ""
        )
        detail = _page(
            finding["title"],
            "<p><a href='index.html'>返回总报告</a></p>"
            "<dl>"
            f"<dt>模块</dt><dd>{html.escape(finding['module'])}</dd>"
            f"<dt>严重程度</dt><dd>{html.escape(finding['severity'])}</dd>"
            f"<dt>证据强度</dt><dd>{html.escape(finding.get('confidence', ''))}</dd>"
            f"<dt>位置</dt><dd>{html.escape(finding.get('url', ''))}</dd>"
            "</dl><h2>证据</h2><pre>" + _pretty(finding.get("evidence", {})) +
            "</pre>" + screenshot_html,
        )
        (run_dir / name).write_text(detail, encoding="utf-8")
    overview = _page(
        "Web 自动化测试报告",
        "<p>目标：" + html.escape(result.get("target", "")) + "</p>"
        "<p>已探索页面：" + str(len(result.get("pages", []))) +
        "；请求计数：" + str(result.get("request_count", 0)) +
        "；发现：" + str(sum(not f.get("suppressed") for f in findings)) + "</p>"
        "<h2>发现的 Bug</h2>"
        "<table><thead><tr><th>标题</th><th>模块</th><th>级别</th>"
        "<th>证据</th><th>位置</th></tr></thead><tbody>" +
        "".join(rows) + "</tbody></table>"
        "<h2>探索记录</h2><pre>" + _pretty(result.get("events", [])) + "</pre>"
        "<h2>静态分析候选位置（非已证实 Bug）</h2><pre>" +
        _pretty(result.get("static_analysis", {})) + "</pre>"
        "<h2>运行说明</h2><pre>" + _pretty(result.get("notes", [])) + "</pre>",
    )
    (run_dir / "index.html").write_text(overview, encoding="utf-8")
    (run_dir / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>" + html.escape(title) + "</title><style>"
        "body{font:16px/1.6 system-ui,sans-serif;max-width:1100px;margin:32px auto;"
        "padding:0 20px;color:#17243a}h1{font-size:28px}h2{margin-top:32px}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #d5dae1;"
        "padding:9px;text-align:left;vertical-align:top}tr:nth-child(even){background:#f7f9fc}"
        "pre{background:#f4f6fa;overflow:auto;padding:14px;border-radius:8px}"
        "dd{margin:0 0 8px 0;overflow-wrap:anywhere}dt{font-weight:700}"
        "</style></head><body><h1>" + html.escape(title) + "</h1>" + body +
        "</body></html>"
    )
