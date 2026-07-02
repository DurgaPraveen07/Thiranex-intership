"""Command-line entry point for the Smart Vulnerability Scanner.

This tool performs only safe, passive checks on systems you own or are
explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import ALLOWED_THREADS, COMMON_PORTS, DEFAULT_THREADS, DEFAULT_TIMEOUT
from port_scanner import enrich_open_ports, scan_ports
from reporter import generate_report
from utils import info, normalize_url, parse_ports, scanning, setup_logging, success, warning
from web_scanner import scan_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smart Vulnerability Scanner - safe defensive assessment only")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Target host or IP for safe port scanning")
    target.add_argument("--url", help="Target website URL for passive web assessment")
    parser.add_argument("--ports", help="Comma-separated ports or ranges, e.g. 80,443,1-1000")
    parser.add_argument("--threads", type=int, choices=ALLOWED_THREADS, default=DEFAULT_THREADS, help="Worker threads")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket and HTTP timeout in seconds")
    parser.add_argument("--report", choices=("console", "json", "html", "all"), default="console", help="Report format")
    return parser


def _scan_host(host: str, port_text: str | None, threads: int, timeout: float, logger) -> dict[str, object]:
    ports = parse_ports(port_text) or COMMON_PORTS
    logger.info("Scanning host %s on %d ports", host, len(ports))
    print(scanning(f"Scanning host {host} ..."))
    port_results = scan_ports(host, ports=ports, threads=threads, timeout=timeout)
    enriched = enrich_open_ports(host, port_results, timeout=timeout)

    open_ports = [item.port for item in enriched if item.state == "OPEN"]
    if open_ports:
        logger.info("Open ports found: %s", ", ".join(str(port) for port in open_ports))
        print(success(f"Open ports: {', '.join(str(port) for port in open_ports)}"))
    else:
        logger.info("No open ports found")
        print(info("No open ports found in the selected range."))

    web_scan: dict[str, object] | None = None
    ssl_scan: dict[str, object] | None = None
    candidate_urls = []
    if 443 in open_ports:
        candidate_urls.append(f"https://{host}")
    if 8080 in open_ports:
        candidate_urls.append(f"http://{host}:8080")
    if 80 in open_ports:
        candidate_urls.append(f"http://{host}")

    if candidate_urls:
        for candidate in candidate_urls:
            try:
                web_scan = scan_url(candidate, timeout=timeout)
                if web_scan.get("ssl"):
                    ssl_scan = web_scan.get("ssl")
                break
            except Exception as exc:  # pragma: no cover - defensive top-level guard
                logger.warning("Web scan for %s failed: %s", candidate, exc)

    return {
        "mode": "host",
        "target": host,
        "ports_requested": ports,
        "port_scan": [item.to_dict() for item in enriched],
        "web_scan": web_scan,
        "ssl_scan": ssl_scan,
    }


def _scan_url(url: str, timeout: float, logger) -> dict[str, object]:
    normalized = normalize_url(url)
    logger.info("Scanning URL %s", normalized)
    print(scanning(f"Scanning website {normalized} ..."))
    web_scan = scan_url(normalized, timeout=timeout)
    return {
        "mode": "url",
        "target": normalized,
        "port_scan": [],
        "web_scan": web_scan,
        "ssl_scan": web_scan.get("ssl"),
    }


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    logger = setup_logging()
    start_time = datetime.now(timezone.utc)
    logger.info("Scan started at %s", start_time.isoformat())

    try:
        if args.host:
            results = _scan_host(args.host, args.ports, args.threads, args.timeout, logger)
        else:
            results = _scan_url(args.url, args.timeout, logger)

        results["start_time"] = start_time.isoformat()
        results["end_time"] = datetime.now(timezone.utc).isoformat()

        warnings: list[str] = []
        if results.get("web_scan"):
            web_scan = results["web_scan"] or {}
            for header in web_scan.get("security_headers", []):
                if header.get("status") in {"Missing", "Weak"}:
                    warnings.append(f"{header.get('header')}: {header.get('status')}")
            for method in web_scan.get("methods", []):
                if method.get("method") == "TRACE" and method.get("allowed"):
                    warnings.append("TRACE appears enabled")
            ssl_status = web_scan.get("ssl", {})
            if ssl_status and ssl_status.get("days_remaining") is not None and ssl_status.get("days_remaining") < 30:
                warnings.append("TLS certificate expires in fewer than 30 days")
        results["warnings"] = warnings

        outputs = generate_report(results, args.report)
        if args.report in {"json", "all"}:
            print(success(f"JSON report saved to: {outputs.get('json')}"))
        if args.report in {"html", "all"}:
            print(success(f"HTML report saved to: {outputs.get('html')}"))
        if args.report in {"console", "all"}:
            print(outputs.get("console", ""))

        logger.info("Scan completed at %s", results["end_time"])
        if warnings:
            logger.warning("Warnings: %s", "; ".join(warnings))
        return 0
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print(warning("Scan interrupted by user."))
        return 130
    except Exception as exc:  # pragma: no cover - top-level safety net
        logger.exception("Fatal scan failure: %s", exc)
        print(warning(f"Fatal error: {exc}"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
