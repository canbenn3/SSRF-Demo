"""Hardened URL-fetch demo: blocks SSRF to private/internal targets."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from adult_filter import adult_content_reason

app = FastAPI(title="Secure Web cURL")
templates = Jinja2Templates(directory="templates")

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
WEB_CURL_TOKEN = os.getenv("WEB_CURL_TOKEN", "").strip()
MOCK_FLAG_TOKEN = os.getenv("MOCK_FLAG_TOKEN", "").strip()
MOCK_WEBSITE_DOMAIN = os.getenv("MOCK_WEBSITE_DOMAIN", "").strip().lower().split(":")[0]
SESSION_COOKIE = "web_curl_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 7
ADULT_FILTER_ENABLED = os.getenv("ADULT_FILTER", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
REQUEST_TIMEOUT = float(os.getenv("FETCH_TIMEOUT_SECONDS", "8"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", "65536"))
MAX_REDIRECTS = 3


def _csv_env(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(
        part.strip().lower().lstrip(".") for part in raw.split(",") if part.strip()
    )


def _whitelisted_ip_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in _csv_env("WHITELISTED_IP_RANGES"):
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            raise RuntimeError(
                f"Invalid CIDR in WHITELISTED_IP_RANGES: {token!r}"
            ) from exc
    return tuple(networks)


WHITELISTED_IP_NETWORKS = _whitelisted_ip_networks()


def _token_matches(submitted: str) -> bool:
    if not WEB_CURL_TOKEN or not submitted:
        return False
    left = hashlib.sha256(submitted.encode("utf-8")).digest()
    right = hashlib.sha256(WEB_CURL_TOKEN.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


def _session_cookie_value() -> str:
    return hmac.new(
        WEB_CURL_TOKEN.encode("utf-8"),
        b"web-curl-session",
        hashlib.sha256,
    ).hexdigest()


def _is_authenticated(request: Request) -> bool:
    if not WEB_CURL_TOKEN:
        return False
    auth = request.headers.get("authorization") or ""
    scheme, _, cred = auth.partition(" ")
    if scheme.lower() == "bearer" and _token_matches(cred.strip()):
        return True
    cookie = request.cookies.get(SESSION_COOKIE, "")
    expected = _session_cookie_value()
    if len(cookie) != len(expected):
        return False
    return hmac.compare_digest(cookie, expected)


def _page_ctx(request: Request, **extra):
    ctx = {
        "authenticated": _is_authenticated(request),
        "safe_browsing_enabled": bool(SAFE_BROWSING_API_KEY),
        "token_configured": bool(WEB_CURL_TOKEN),
        "result": None,
        "error": None,
        "url": "",
        "auth_error": None,
    }
    ctx.update(extra)
    return ctx


class FetchDenied(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _canonical_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_whitelisted_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = _canonical_ip(ip)
    return any(ip in network for network in WHITELISTED_IP_NETWORKS)


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = _canonical_ip(ip)
    if _is_whitelisted_ip(ip):
        return False
    return any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
            # Cloud metadata / CGNAT / special-use ranges commonly abused in SSRF
            ip in ipaddress.ip_network("100.64.0.0/10"),
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


def _parse_url(url: str) -> str:
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
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip):
            raise FetchDenied(f"Blocked IP address: {host}")
        return str(ip)
    except ValueError:
        pass
    return host


def _adult_content_check(url: str) -> None:
    if not ADULT_FILTER_ENABLED:
        return
    reason = adult_content_reason(url, timeout=REQUEST_TIMEOUT)
    if reason:
        raise FetchDenied(reason)


def _safe_browsing_check(url: str) -> Optional[str]:
    """Return a threat description if unsafe, None if OK / skipped."""
    if not SAFE_BROWSING_API_KEY:
        return None

    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {"x-goog-api-key": SAFE_BROWSING_API_KEY}
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
        resp = requests.post(
            endpoint, json=body, headers=headers, timeout=REQUEST_TIMEOUT
        )
        if not resp.ok:
            detail = resp.text.strip()
            try:
                err = resp.json().get("error") or {}
                detail = err.get("message") or detail
            except ValueError:
                pass
            raise FetchDenied(
                f"Safe Browsing check failed: HTTP {resp.status_code} {detail}"
            )
        data = resp.json()
    except FetchDenied:
        raise
    except requests.RequestException as exc:
        raise FetchDenied(f"Safe Browsing check failed: {exc}") from exc

    matches = data.get("matches") or []
    if matches:
        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return ", ".join(threats)
    return None


def _flag_inject_hosts() -> set[str]:
    hosts = {"mock-website"}
    if MOCK_WEBSITE_DOMAIN:
        hosts.add(MOCK_WEBSITE_DOMAIN.rstrip("."))
    return hosts


def _should_inject_flag_token(url: str) -> bool:
    if not MOCK_FLAG_TOKEN:
        return False
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    path = (parsed.path or "/").rstrip("/") or "/"
    return path == "/flag" and host in _flag_inject_hosts()


def _upstream_request(url: str, headers: dict):
    kwargs = {
        "timeout": REQUEST_TIMEOUT,
        "allow_redirects": False,
        "stream": True,
        "headers": headers,
    }
    if _should_inject_flag_token(url):
        return requests.post(url, json={"token": MOCK_FLAG_TOKEN}, **kwargs)
    return requests.get(url, **kwargs)


def safe_fetch(url: str) -> dict:
    current = url
    host = _parse_url(current)
    t = _adult_content_check(current)
    _resolve_and_validate_host(host)

    threat = _safe_browsing_check(current)
    if threat:
        raise FetchDenied(f"Safe Browsing blocked this URL ({threat})")

    headers = {"User-Agent": "secure-web-curl/1.0"}

    try:
        for _ in range(MAX_REDIRECTS + 1):
            print("URL: ", current)
            with _upstream_request(current, headers) as resp:
                if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise FetchDenied("Redirect without Location header")
                    next_url = urljoin(current, location)
                    host = _parse_url(next_url)
                    _adult_content_check(next_url)
                    _resolve_and_validate_host(host)
                    threat = _safe_browsing_check(next_url)
                    if threat:
                        raise FetchDenied(
                            f"Safe Browsing blocked this URL ({threat})"
                        )
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
        _page_ctx(request),
    )


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, token: str = Form("")):
    token = token.strip()
    if not WEB_CURL_TOKEN:
        return templates.TemplateResponse(
            request,
            "index.html",
            _page_ctx(request, auth_error="Access token is not configured"),
            status_code=503,
        )
    if not _token_matches(token):
        return templates.TemplateResponse(
            request,
            "index.html",
            _page_ctx(request, auth_error="Invalid token"),
            status_code=401,
        )
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        _session_cookie_value(),
        httponly=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
    )
    return response


@app.post("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.post("/fetch", response_class=HTMLResponse)
async def fetch(request: Request, url: str = Form(...)):
    if not _is_authenticated(request):
        return templates.TemplateResponse(
            request,
            "index.html",
            _page_ctx(request, auth_error="Authentication required"),
            status_code=401,
        )
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
        _page_ctx(request, result=result, error=error, url=url),
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "safe_browsing_enabled": bool(SAFE_BROWSING_API_KEY),
    }
