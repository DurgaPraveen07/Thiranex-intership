"""Passive website checks, HTTP method discovery, SSL inspection, and tech detection."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from config import HTTP_METHODS, SAFE_DIRECTORIES, SAFE_WEB_PATHS, DEFAULT_TIMEOUT
from headers import analyze_security_headers, HeaderCheck
from utils import create_session


@dataclass(slots=True)
class PathResult:
    path: str
    status_code: int | None
    found: bool
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class MethodResult:
    method: str
    allowed: bool
    status_code: int | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class SSLResult:
    host: str
    port: int
    tls_version: str = ""
    issuer: str = ""
    expiration_date: str = ""
    days_remaining: int | None = None
    status: str = "Unknown"
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _request(session: requests.Session, method: str, url: str, timeout: float, allow_redirects: bool = False) -> requests.Response:
    return session.request(method, url, timeout=timeout, allow_redirects=allow_redirects, verify=False)


def fetch_root(session: requests.Session, url: str, timeout: float = DEFAULT_TIMEOUT) -> requests.Response | None:
    for method in ("GET", "HEAD"):
        try:
            response = _request(session, method, url, timeout, allow_redirects=True)
            return response
        except requests.RequestException:
            continue
    return None


def check_path(session: requests.Session, base_url: str, path: str, timeout: float = DEFAULT_TIMEOUT) -> PathResult:
    candidate = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        response = _request(session, "HEAD", candidate, timeout, allow_redirects=False)
        if response.status_code in {405, 501}:
            response = _request(session, "GET", candidate, timeout, allow_redirects=False)
        found = response.status_code not in {404, 410}
        return PathResult(path=path, status_code=response.status_code, found=found)
    except requests.RequestException as exc:
        return PathResult(path=path, status_code=None, found=False, note=str(exc))


def scan_web_paths(base_url: str, session: requests.Session | None = None, timeout: float = DEFAULT_TIMEOUT) -> list[PathResult]:
    active_session = session or create_session(timeout)
    candidates = list(dict.fromkeys([*SAFE_WEB_PATHS, *SAFE_DIRECTORIES]))
    return [check_path(active_session, base_url, path, timeout) for path in candidates]


def check_http_methods(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> list[MethodResult]:
    session = create_session(timeout)
    results: list[MethodResult] = []
    allow_header = ""

    try:
        options_response = session.request("OPTIONS", base_url, timeout=timeout, allow_redirects=False, verify=False)
        allow_header = options_response.headers.get("Allow", "") or options_response.headers.get("Access-Control-Allow-Methods", "")
    except requests.RequestException:
        options_response = None

    advertised_methods = {item.strip().upper() for item in allow_header.split(",") if item.strip()}

    for method in HTTP_METHODS:
        if method in {"POST", "PUT", "DELETE"}:
            allowed = method in advertised_methods
            status_code = options_response.status_code if options_response is not None else None
            results.append(MethodResult(method=method, allowed=allowed, status_code=status_code))
            continue

        try:
            response = session.request(method, base_url, timeout=timeout, allow_redirects=False, verify=False)
            if method == "OPTIONS" and allow_header:
                allowed = True
            else:
                allowed = response.status_code not in {405, 501}
            results.append(MethodResult(method=method, allowed=allowed, status_code=response.status_code))
        except requests.RequestException:
            results.append(MethodResult(method=method, allowed=False, status_code=None))
    return results


def detect_technologies(response: requests.Response | None) -> list[dict[str, str]]:
    if response is None:
        return []

    headers = {key.lower(): value for key, value in response.headers.items()}
    html = response.text or ""
    soup = BeautifulSoup(html, "html.parser")
    technologies: list[dict[str, str]] = []

    def add(name: str, evidence: str) -> None:
        if name not in [entry["technology"] for entry in technologies]:
            technologies.append({"technology": name, "evidence": evidence})

    server = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")
    if "apache" in server.lower():
        add("Apache", f"Server: {server}")
    if "nginx" in server.lower():
        add("Nginx", f"Server: {server}")
    if "microsoft-iis" in server.lower() or "asp.net" in x_powered_by.lower():
        add("IIS", f"Server/X-Powered-By: {server or x_powered_by}")
        add("ASP.NET", f"X-Powered-By: {x_powered_by or server}")
    if "cloudflare" in server.lower() or "cf-ray" in headers:
        add("Cloudflare", "Cloudflare headers detected")
    if "php" in x_powered_by.lower():
        add("PHP", f"X-Powered-By: {x_powered_by}")
    if "node" in x_powered_by.lower() or "express" in x_powered_by.lower():
        add("Node.js", f"X-Powered-By: {x_powered_by}")

    generator = (soup.find("meta", attrs={"name": "generator"}) or {}).get("content", "")
    if "wordpress" in generator.lower() or "wp-content" in html.lower() or "wp-includes" in html.lower():
        add("WordPress", generator or "WordPress assets found")
    if "laravel" in generator.lower() or "laravel" in html.lower():
        add("Laravel", generator or "Laravel markers found")

    if "react" in html.lower() or "__next_data__" in html.lower() or "data-reactroot" in html.lower():
        add("React", "React-related DOM markers detected")
    if "vue" in html.lower() or "data-v-" in html.lower():
        add("Vue", "Vue-related DOM markers detected")
    if "bootstrap" in html.lower() or any("bootstrap" in (tag.get("href", "") + tag.get("src", "")).lower() for tag in soup.find_all(["link", "script"])):
        add("Bootstrap", "Bootstrap asset reference found")

    return technologies


def check_ssl(url: str, timeout: float = DEFAULT_TIMEOUT) -> SSLResult:
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    port = parsed.port or 443
    result = SSLResult(host=hostname, port=port)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                result.tls_version = tls_socket.version() or ""
                issuer = cert.get("issuer", ())
                result.issuer = ", ".join(
                    ":".join(part) for part in issuer if isinstance(part, tuple) and len(part) == 2
                )
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiration = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result.expiration_date = expiration.isoformat()
                    result.days_remaining = (expiration - datetime.now(timezone.utc)).days
                result.status = "Valid"
    except ssl.SSLError as exc:
        result.status = "SSL Error"
        result.error = str(exc)
    except (socket.timeout, TimeoutError) as exc:
        result.status = "Timeout"
        result.error = str(exc)
    except OSError as exc:
        result.status = "Connection Error"
        result.error = str(exc)

    return result


def scan_security_headers(url: str, timeout: float = DEFAULT_TIMEOUT) -> list[HeaderCheck]:
    session = create_session(timeout)
    response = fetch_root(session, url, timeout)
    if response is None:
        return []
    return analyze_security_headers(response.headers)


def scan_http_methods(url: str, timeout: float = DEFAULT_TIMEOUT) -> list[MethodResult]:
    return check_http_methods(url, timeout)


def scan_url(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict[str, object]:
    session = create_session(timeout)
    root_response = fetch_root(session, url, timeout)
    if root_response is None:
        return {
            "root": None,
            "security_headers": [],
            "ssl": None,
            "methods": [],
            "paths": [],
            "technologies": [],
        }

    root_data = {
        "url": root_response.url,
        "status_code": root_response.status_code,
        "headers": dict(root_response.headers),
    }

    return {
        "root": root_data,
        "security_headers": [item.to_dict() for item in analyze_security_headers(root_response.headers)],
        "ssl": check_ssl(root_response.url, timeout).to_dict() if root_response.url.startswith("https://") else None,
        "methods": [item.to_dict() for item in check_http_methods(root_response.url, timeout)],
        "paths": [item.to_dict() for item in scan_web_paths(root_response.url, session, timeout)],
        "technologies": detect_technologies(root_response),
    }
