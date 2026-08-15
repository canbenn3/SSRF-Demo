"""Hardened URL-fetch demo: blocks SSRF to private/internal targets."""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Secure Web cURL")
templates = Jinja2Templates(directory="templates")

# Comma-separated hostnames allowed for fetch (override via env).
DEFAULT_ALLOWLIST = "example.com,www.example.com,httpbin.org"
ALLOWLIST = {
    h.strip().lower()
    for h in os.getenv("URL_ALLOWLIST", DEFAULT_ALLOWLIST).split(",")
    if h.strip()
}

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
REQUEST_TIMEOUT = float(os.getenv("FETCH_TIMEOUT_SECONDS", "8"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "65536"))
MAX_REDIRECTS = 3


class FetchDenied(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
            # Cloud metadata / special-use ranges commonly abused in SSRF
            ip in ipaddress.ip_network("169.254.0.0/16"),
            ip in ipaddress.ip_network("::1/128"),
            ip in ipaddress.ip_network("fc00::/7"),
            ip in ipaddress.ip_network("fe80::/10"),
        )
    )


def _resolve_and_validate_host(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchDenied(f"DNS resolution failed for {hostname!r}") from exc

    resolved: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        ip = ipaddress.ip_address(ip_str)
        if _is_blocked_ip(ip):
            raise FetchDenied(
                f"Refusing to fetch {hostname!r}: resolves to blocked address {ip_str}"
            )
        resolved.append(ip_str)

    if not resolved:
        raise FetchDenied(f"No usable addresses for {hostname!r}")
    return resolved


def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchDenied("Only http and https URLs are allowed")
    if not parsed.hostname:
        raise FetchDenied("URL must include a hostname")
    if parsed.username or parsed.password:
        raise FetchDenied("URLs with embedded credentials are not allowed")
    if parsed.port not in (None, 80, 443):
        raise FetchDenied("Only ports 80 and 443 are allowed")

    host = parsed.hostname.lower().rstrip(".")
    # Literal IPs are never allowlisted for this demo
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip):
            raise FetchDenied(f"Blocked IP address: {host}")
        raise FetchDenied("Literal IP addresses are not allowed; use an allowlisted hostname")
    except ValueError:
        pass

    if host not in ALLOWLIST:
        raise FetchDenied(
            f"Host {host!r} is not on the allowlist. "
            f"Allowed: {', '.join(sorted(ALLOWLIST))}"
        )

    _resolve_and_validate_host(host)
    return host


def _safe_browsing_check(url: str) -> Optional[str]:
    """Return a threat description if unsafe, None if OK / skipped."""
    if not SAFE_BROWSING_API_KEY:
        return None

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_API_KEY}"
    )
    body = {
        "client": {"clientId": "ssrf-demo-secure-curl", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        raise FetchDenied(f"Safe Browsing check failed: {exc}") from exc

    matches = data.get("matches") or []
    if matches:
        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return ", ".join(threats)
    return None


def safe_fetch(url: str) -> dict:
    current = url
    host = _validate_url(current)

    threat = _safe_browsing_check(current)
    if threat:
        raise FetchDenied(f"Safe Browsing blocked this URL ({threat})")

    headers = {"User-Agent": "secure-web-curl/1.0"}

    try:
        for _ in range(MAX_REDIRECTS + 1):
            with requests.get(
                current,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
                headers=headers,
            ) as resp:
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise FetchDenied("Redirect without Location header")
                    next_url = urljoin(current, location)
                    host = _validate_url(next_url)
                    current = next_url
                    continue

                content = resp.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True)
                truncated = len(content) > MAX_RESPONSE_BYTES
                body = content[:MAX_RESPONSE_BYTES]
                text = body.decode("utf-8", errors="replace")
                return {
                    "ok": True,
                    "requested_url": url,
                    "final_url": current,
                    "status_code": resp.status_code,
                    "resolved_host": host,
                    "truncated": truncated,
                    "body": text,
                }

        raise FetchDenied("Too many redirects")
    except FetchDenied:
        raise
    except requests.RequestException as exc:
        raise FetchDenied(f"Upstream request failed: {exc}") from exc


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "allowlist": sorted(ALLOWLIST),
            "safe_browsing_enabled": bool(SAFE_BROWSING_API_KEY),
            "result": None,
            "error": None,
            "url": "",
        },
    )


@app.post("/fetch", response_class=HTMLResponse)
async def fetch(request: Request, url: str = Form(...)):
    url = url.strip()
    result = None
    error = None
    try:
        result = safe_fetch(url)
    except FetchDenied as exc:
        error = exc.reason
    except Exception as exc:  # noqa: BLE001 — surface unexpected errors in demo UI
        error = f"Unexpected error: {exc}"

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "allowlist": sorted(ALLOWLIST),
            "safe_browsing_enabled": bool(SAFE_BROWSING_API_KEY),
            "result": result,
            "error": error,
            "url": url,
        },
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "allowlist_size": len(ALLOWLIST),
        "safe_browsing_enabled": bool(SAFE_BROWSING_API_KEY),
    }
