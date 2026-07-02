"""Shared utility helpers used by the scanner modules."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from datetime import datetime
from typing import Iterable
from urllib.parse import urlparse

import requests
import urllib3
from colorama import Fore, Style, init as colorama_init

from config import REPORTS_DIRNAME

colorama_init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def project_root() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def reports_dir() -> str:
    path = os.path.join(project_root(), REPORTS_DIRNAME)
    os.makedirs(path, exist_ok=True)
    return path


def timestamp_slug() -> str:
    return datetime.now().strftime("%Y_%m_%d_%H%M%S")


def build_output_path(prefix: str, extension: str) -> str:
    filename = f"{prefix}_{timestamp_slug()}.{extension.lstrip('.') }"
    return os.path.join(reports_dir(), filename)


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("smart_vulnerability_scanner")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    log_path = os.path.join(reports_dir(), f"scan_{timestamp_slug()}.log")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False
    logger.info("Log file: %s", log_path)
    return logger


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def info(text: str) -> str:
    return color_text(text, Fore.YELLOW)


def success(text: str) -> str:
    return color_text(text, Fore.GREEN)


def warning(text: str) -> str:
    return color_text(text, Fore.RED)


def scanning(text: str) -> str:
    return color_text(text, Fore.BLUE)


def parse_ports(port_value: str | None) -> list[int]:
    if not port_value:
        return []

    ports: set[int] = set()
    for chunk in port_value.split(","):
        item = chunk.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(item)
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme:
        return f"https://{value}"
    return value


def is_probable_hostname(value: str) -> bool:
    if is_valid_ip(value):
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9.-]+", value))


def create_session(timeout: float) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "SmartVulnScanner/1.0 (authorized defensive assessment)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    session.request_timeout = timeout  # type: ignore[attr-defined]
    return session


def safe_json_dump(data: object, path: str) -> None:
    with open(path, "w", encoding="utf-8") as file_handle:
        json.dump(data, file_handle, indent=2, sort_keys=True, default=str)


def flatten(values: Iterable[Iterable[str]]) -> list[str]:
    flattened: list[str] = []
    for group in values:
        flattened.extend(group)
    return flattened
