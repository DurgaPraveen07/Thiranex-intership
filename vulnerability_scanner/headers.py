"""HTTP security header analysis."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Mapping

from config import SECURITY_HEADERS


@dataclass(slots=True)
class HeaderCheck:
    header: str
    status: str
    value: str = ""
    details: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _is_hsts_weak(value: str) -> bool:
    lowered = value.lower()
    if "max-age" not in lowered:
        return True
    try:
        max_age_part = next(part for part in lowered.split(";") if "max-age" in part)
        max_age = int(max_age_part.split("=", 1)[1].strip())
        return max_age < 15552000
    except (StopIteration, ValueError, IndexError):
        return True


def _is_csp_weak(value: str) -> bool:
    lowered = value.lower()
    weak_markers = ["unsafe-inline", "unsafe-eval", "default-src *", "script-src *"]
    return any(marker in lowered for marker in weak_markers)


def _is_x_xss_weak(value: str) -> bool:
    lowered = value.lower().strip()
    return lowered in {"0", "disabled", "off"}


def _is_permissions_policy_weak(value: str) -> bool:
    lowered = value.lower()
    return not value.strip() or "*" in lowered or "()" in lowered


def analyze_security_headers(headers: Mapping[str, str]) -> list[HeaderCheck]:
    normalized = {key.lower(): value for key, value in headers.items()}
    results: list[HeaderCheck] = []

    for header in SECURITY_HEADERS:
        value = normalized.get(header.lower(), "")
        if not value:
            results.append(HeaderCheck(header=header, status="Missing"))
            continue

        if header == "Strict-Transport-Security" and _is_hsts_weak(value):
            results.append(HeaderCheck(header=header, status="Weak", value=value, details="Low or missing max-age"))
        elif header == "Content-Security-Policy" and _is_csp_weak(value):
            results.append(HeaderCheck(header=header, status="Weak", value=value, details="Broad or unsafe directives detected"))
        elif header == "X-XSS-Protection" and _is_x_xss_weak(value):
            results.append(HeaderCheck(header=header, status="Weak", value=value, details="Protection disabled"))
        elif header == "Permissions-Policy" and _is_permissions_policy_weak(value):
            results.append(HeaderCheck(header=header, status="Weak", value=value, details="Policy appears permissive or empty"))
        else:
            results.append(HeaderCheck(header=header, status="Present", value=value))

    return results
