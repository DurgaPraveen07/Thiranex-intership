"""Fast TCP port scanning and safe banner grabbing utilities."""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Iterable

from config import COMMON_PORTS, DEFAULT_TIMEOUT


@dataclass(slots=True)
class PortResult:
    port: int
    state: str
    service: str = ""
    version: str = ""
    banner: str = ""

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


def probe_port(host: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "OPEN"
    except ConnectionRefusedError:
        return "CLOSED"
    except (socket.timeout, TimeoutError):
        return "FILTERED"
    except OSError:
        return "FILTERED"


def scan_ports(host: str, ports: Iterable[int] | None = None, threads: int = 25, timeout: float = DEFAULT_TIMEOUT) -> list[PortResult]:
    ports_to_scan = list(ports or COMMON_PORTS)
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(probe_port, host, port, timeout): port for port in ports_to_scan
        }
        for future in as_completed(future_map):
            port = future_map[future]
            state = future.result()
            results.append(PortResult(port=port, state=state))

    return sorted(results, key=lambda item: item.port)


def _read_socket_banner(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    try:
        data = sock.recv(1024)
    except socket.timeout:
        return ""
    return data.decode("utf-8", errors="ignore").strip()


def _http_banner(host: str, port: int, timeout: float, use_ssl: bool) -> str:
    request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: SmartVulnScanner/1.0\r\nConnection: close\r\n\r\n"
    raw_socket = socket.create_connection((host, port), timeout=timeout)
    try:
        connection: socket.socket
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(raw_socket, server_hostname=host)
        else:
            connection = raw_socket
        with connection:
            connection.sendall(request.encode("ascii", errors="ignore"))
            return _read_socket_banner(connection, timeout)
    finally:
        raw_socket.close()


def detect_service_from_banner(port: int, banner: str) -> tuple[str, str]:
    normalized = banner.lower()

    patterns = [
        ("Apache", re.compile(r"apache/?([0-9.\-a-zA-Z]*)", re.I)),
        ("Nginx", re.compile(r"nginx/?([0-9.\-a-zA-Z]*)", re.I)),
        ("IIS", re.compile(r"microsoft-iis/?([0-9.\-a-zA-Z]*)", re.I)),
        ("OpenSSH", re.compile(r"openssh[_\s]?([0-9.]+)", re.I)),
        ("vsFTPd", re.compile(r"vsftpd\s+([0-9.]+)", re.I)),
        ("MySQL", re.compile(r"mysql.*?(?:\x00|\s)([0-9.]+)", re.I)),
    ]

    for service, pattern in patterns:
        match = pattern.search(banner)
        if match:
            version = match.group(1).strip("/; ") if match.groups() else ""
            return service, version

    if port == 22 and "ssh" in normalized:
        version_match = re.search(r"openssh[_\s]?([0-9.]+)", banner, re.I)
        return "OpenSSH", version_match.group(1) if version_match else ""
    if port == 21 and "ftp" in normalized:
        return "FTP", ""
    if port == 25 and "smtp" in normalized:
        return "SMTP", ""
    if port == 110 and "pop3" in normalized:
        return "POP3", ""
    if port == 143 and "imap" in normalized:
        return "IMAP", ""
    if port == 3306 and banner:
        version_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", banner)
        return "MySQL", version_match.group(1) if version_match else ""
    if port in {80, 443, 8080} and banner:
        if "server:" in normalized:
            server_match = re.search(r"server:\s*([^\r\n]+)", banner, re.I)
            if server_match:
                server_text = server_match.group(1).strip()
                if "apache" in server_text.lower():
                    version_match = re.search(r"apache/?([0-9.\-a-zA-Z]*)", server_text, re.I)
                    return "Apache", version_match.group(1) if version_match else ""
                if "nginx" in server_text.lower():
                    version_match = re.search(r"nginx/?([0-9.\-a-zA-Z]*)", server_text, re.I)
                    return "Nginx", version_match.group(1) if version_match else ""
                if "microsoft-iis" in server_text.lower():
                    version_match = re.search(r"microsoft-iis/?([0-9.\-a-zA-Z]*)", server_text, re.I)
                    return "IIS", version_match.group(1) if version_match else ""

    return "", ""


def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortResult:
    state = probe_port(host, port, timeout)
    if state != "OPEN":
        return PortResult(port=port, state=state)

    banner = ""
    service = ""
    version = ""

    try:
        if port in {21, 22, 25, 110, 143, 3306}:
            with socket.create_connection((host, port), timeout=timeout) as connection:
                banner = _read_socket_banner(connection, timeout)
        elif port in {80, 8080}:
            banner = _http_banner(host, port, timeout, use_ssl=False)
        elif port == 443:
            banner = _http_banner(host, port, timeout, use_ssl=True)
    except (socket.timeout, TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError):
        banner = ""

    if banner:
        service, version = detect_service_from_banner(port, banner)

    return PortResult(port=port, state=state, service=service, version=version, banner=banner)


def enrich_open_ports(host: str, port_results: list[PortResult], timeout: float = DEFAULT_TIMEOUT) -> list[PortResult]:
    enriched: list[PortResult] = []
    for result in port_results:
        if result.state == "OPEN":
            enriched.append(grab_banner(host, result.port, timeout=timeout))
        else:
            enriched.append(result)
    return enriched
