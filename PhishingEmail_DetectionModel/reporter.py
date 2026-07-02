"""Report generation for console, JSON, and HTML output."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any

from colorama import Fore, Style

from utils import build_output_path, safe_json_dump


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


def _status_class(status: str) -> str:
    lowered = status.lower()
    if lowered in {"open", "present", "valid"}:
        return "good"
    if lowered in {"missing", "closed", "not found"}:
        return "bad"
    if lowered in {"weak", "filtered", "ssl error", "timeout", "connection error"}:
        return "warn"
    return "neutral"


def _rows_from_collection(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<tr><td colspan='5'>No data</td></tr>"

    rows = []
    for item in items:
        rows.append("<tr>" + "".join(f"<td>{html.escape(_stringify(value))}</td>" for value in item.values()) + "</tr>")
    return "\n".join(rows)


def generate_json_report(results: dict[str, Any], prefix: str = "report") -> str:
    output_path = build_output_path(prefix, "json")
    safe_json_dump(results, output_path)
    return output_path


def generate_console_report(results: dict[str, Any]) -> str:
    lines = [
        f"{Fore.CYAN}Smart Vulnerability Scanner Report{Style.RESET_ALL}",
        f"Target: {results.get('target', 'Unknown')}",
        f"Start: {results.get('start_time', 'Unknown')}",
        f"End: {results.get('end_time', 'Unknown')}",
        "",
    ]

    port_results = results.get("port_scan", [])
    if port_results:
        lines.append("Ports:")
        for item in port_results:
            lines.append(
                f"  Port {item.get('port')}: {item.get('state')}"
                + (f" | {item.get('service')} {item.get('version')}".rstrip() if item.get("service") else "")
            )
        lines.append("")

    if results.get("web_scan"):
        lines.append("Website Checks:")
        web_scan = results["web_scan"]
        for section in ("paths", "security_headers", "methods", "technologies"):
            if web_scan.get(section):
                lines.append(f"  {section}:")
                for item in web_scan[section]:
                    lines.append(f"    {item}")
        lines.append("")

    for warning in results.get("warnings", []):
        lines.append(f"{Fore.RED}Warning:{Style.RESET_ALL} {warning}")

    return "\n".join(lines)


def generate_html_report(results: dict[str, Any], prefix: str = "report") -> str:
    output_path = build_output_path(prefix, "html")
    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Smart Vulnerability Scanner Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --panel: #111827;
      --text: #e5e7eb;
      --muted: #94a3b8;
      --good: #22c55e;
      --bad: #ef4444;
      --warn: #f59e0b;
      --accent: #38bdf8;
      --line: #1f2937;
    }}
    body {{ margin: 0; font-family: Arial, sans-serif; background: linear-gradient(180deg, #020617, var(--bg)); color: var(--text); }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 64px; }}
    .hero {{ background: rgba(17,24,39,0.9); border: 1px solid var(--line); border-radius: 20px; padding: 24px; box-shadow: 0 20px 60px rgba(0,0,0,0.25); }}
    h1, h2 {{ margin: 0 0 12px; }}
    .meta {{ color: var(--muted); display: grid; gap: 6px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
    .card {{ margin-top: 20px; background: rgba(17,24,39,0.92); border: 1px solid var(--line); border-radius: 18px; padding: 20px; }}
    table {{ width: 100%; border-collapse: collapse; overflow: hidden; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--accent); font-size: 0.92rem; }}
    tr:hover td {{ background: rgba(56,189,248,0.05); }}
    .good {{ color: var(--good); }}
    .bad {{ color: var(--bad); }}
    .warn {{ color: var(--warn); }}
    .neutral {{ color: var(--muted); }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #020617; border: 1px solid var(--line); padding: 14px; border-radius: 14px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
    .pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: rgba(56,189,248,0.1); color: var(--accent); margin-right: 8px; margin-bottom: 8px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Smart Vulnerability Scanner</h1>
      <div class="meta">
        <div><strong>Target</strong><br>{html.escape(str(results.get('target', 'Unknown')))}</div>
        <div><strong>Start</strong><br>{html.escape(str(results.get('start_time', 'Unknown')))}</div>
        <div><strong>End</strong><br>{html.escape(str(results.get('end_time', 'Unknown')))}</div>
        <div><strong>Mode</strong><br>{html.escape(str(results.get('mode', 'Unknown')))}</div>
      </div>
    </section>

    <section class="card">
      <h2>Port Scan</h2>
      <table>
        <thead><tr><th>Port</th><th>Status</th><th>Service</th><th>Version</th><th>Banner</th></tr></thead>
        <tbody>
          {''.join(
            '<tr>'
            f'<td>{item.get("port", "")}</td>'
            f'<td class="{_status_class(str(item.get("state", "")))}">{html.escape(str(item.get("state", "")))}</td>'
            f'<td>{html.escape(str(item.get("service", "")))}</td>'
            f'<td>{html.escape(str(item.get("version", "")))}</td>'
            f'<td><pre>{html.escape(str(item.get("banner", "")))}</pre></td>'
            '</tr>'
            for item in results.get('port_scan', [])
          ) or '<tr><td colspan="5">No port data</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="grid">
      <div class="card">
        <h2>Security Headers</h2>
        <table>
          <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Details</th></tr></thead>
          <tbody>
            {''.join(
              '<tr>'
              f'<td>{html.escape(str(item.get("header", "")))}</td>'
              f'<td class="{_status_class(str(item.get("status", "")))}">{html.escape(str(item.get("status", "")))}</td>'
              f'<td>{html.escape(str(item.get("value", "")))}</td>'
              f'<td>{html.escape(str(item.get("details", "")))}</td>'
              '</tr>'
              for item in results.get('web_scan', {}).get('security_headers', [])
            ) or '<tr><td colspan="4">No data</td></tr>'}
          </tbody>
        </table>
      </div>
      <div class="card">
        <h2>SSL</h2>
        <pre>{html.escape(json.dumps(results.get('web_scan', {}).get('ssl'), indent=2, default=str))}</pre>
      </div>
    </section>

    <section class="card">
      <h2>Paths</h2>
      <table>
        <thead><tr><th>Path</th><th>Status Code</th><th>Found</th><th>Note</th></tr></thead>
        <tbody>
          {''.join(
            '<tr>'
            f'<td>{html.escape(str(item.get("path", "")))}</td>'
            f'<td>{html.escape(str(item.get("status_code", "")))}</td>'
            f'<td class="{_status_class("present" if item.get("found") else "missing")}">{html.escape(str(item.get("found", "")))}</td>'
            f'<td>{html.escape(str(item.get("note", "")))}</td>'
            '</tr>'
            for item in results.get('web_scan', {}).get('paths', [])
          ) or '<tr><td colspan="4">No data</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="grid">
      <div class="card">
        <h2>Methods</h2>
        <div>
          {''.join(
            f'<span class="pill {"good" if item.get("allowed") else "warn"}">{html.escape(str(item.get("method", "")))}: {html.escape(str(item.get("status_code", "")))}</span>'
            for item in results.get('web_scan', {}).get('methods', [])
          ) or 'No data'}
        </div>
      </div>
      <div class="card">
        <h2>Technologies</h2>
        <div>
          {''.join(
            f'<span class="pill">{html.escape(str(item.get("technology", "")))}: {html.escape(str(item.get("evidence", "")))}</span>'
            for item in results.get('web_scan', {}).get('technologies', [])
          ) or 'No data'}
        </div>
      </div>
    </section>
  </div>
</body>
</html>"""
    with open(output_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(html_text)
    return output_path


def generate_report(results: dict[str, Any], report_type: str = "console") -> dict[str, str]:
    outputs: dict[str, str] = {}
    if report_type in {"json", "all"}:
        outputs["json"] = generate_json_report(results)
    if report_type in {"html", "all"}:
        outputs["html"] = generate_html_report(results)
    if report_type in {"console", "all"}:
        outputs["console"] = generate_console_report(results)
    return outputs
