"""Central configuration for the Smart Vulnerability Scanner.

All checks are intentionally passive and designed for authorized, defensive
assessment only.
"""

from __future__ import annotations

DEFAULT_TIMEOUT = 1.5
DEFAULT_THREADS = 25
ALLOWED_THREADS = (10, 25, 50, 100)

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    8080,
]

SAFE_WEB_PATHS = [
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/config.php.bak",
    "/admin",
    "/login",
    "/dashboard",
]

SAFE_DIRECTORIES = [
    "/admin",
    "/login",
    "/test",
    "/dev",
    "/uploads",
    "/images",
    "/assets",
    "/api",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "HEAD"]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Content-Type-Options",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
]

TECH_SIGNATURES = [
    "Apache",
    "Nginx",
    "IIS",
    "Cloudflare",
    "PHP",
    "ASP.NET",
    "Node.js",
    "WordPress",
    "Laravel",
    "React",
    "Vue",
    "Bootstrap",
]

REPORTS_DIRNAME = "reports"
