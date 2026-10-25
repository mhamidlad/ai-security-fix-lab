"""Lab 7: Server-Side Request Forgery (SSRF) — Vulnerable implementation."""

import urllib.request
from urllib.parse import urlparse


# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: No URL validation, requests any URL
# ──────────────────────────────────────────────────────────────────────────

def fetch_url_vulnerable(url: str) -> str:
    """VULNERABLE: Fetches any URL the user provides."""
    # VULNERABILITY: Can access internal services, cloud metadata endpoints
    # Input: "http://169.254.169.254/latest/meta-data/" would get AWS credentials
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8", errors="replace")


# ──────────────────────────────────────────────────────────────────────────
# SECURE: URL allowlist, blocks private IPs and metadata endpoints
# ──────────────────────────────────────────────────────────────────────────

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com", "public-data.example.org"}

BLOCKED_IP_PREFIXES = (
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "0.0.0.0", "::1", "fc00:", "fe80:",
)


def fetch_url_secure(url: str) -> str:
    """SECURE: Validates URL, blocks internal addresses, enforces allowlist."""
    parsed = urlparse(url)
    
    # Validate scheme
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) URLs are allowed")
    
    # Check host against allowlist
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host '{parsed.hostname}' is not in the allowlist")
    
    # Block metadata endpoints
    if parsed.hostname and any(
        parsed.hostname.startswith(prefix) for prefix in BLOCKED_IP_PREFIXES
    ):
        raise ValueError("Internal IP addresses are blocked")
    
    # Fetch with timeout
    req = urllib.request.Request(url, headers={"User-Agent": "SSRF-Safe-Fetcher/1.0"})
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.read().decode("utf-8", errors="replace")
