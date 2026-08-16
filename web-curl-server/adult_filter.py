"""Best-effort adult-content blocking: env lists plus Cloudflare family DNS."""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import unquote, urlparse

import requests

_SINKHOLE = frozenset(
    {
        ipaddress.ip_address("0.0.0.0"),
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::"),
        ipaddress.ip_address("::1"),
    }
)

FAMILY_DOH_URL = "https://family.cloudflare-dns.com/dns-query"


def _csv_env(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(part.strip().lower().lstrip(".") for part in raw.split(",") if part.strip())


def _normalize_host(host: str) -> str:
    host = host.lower().rstrip(".")
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def _labels(host: str) -> list[str]:
    return [part for part in _normalize_host(host).split(".") if part]


def _domain_blocked(host: str) -> bool:
    host = _normalize_host(host)
    labels = _labels(host)
    if not labels:
        return False

    for token in _csv_env("ADULT_DOMAINS"):
        if "." in token:
            if host == token or host.endswith("." + token):
                return True
            continue
        # Undotted entries match a DNS label or the TLD (not substrings).
        if token in labels:
            return True
    return False


def _path_blocked(url: str) -> bool:
    blocked = _csv_env("ADULT_PATHS")
    if not blocked:
        return False
    parsed = urlparse(url)
    path = unquote(parsed.path or "").lower()
    segments = [seg for seg in path.split("/") if seg]
    return any(seg in blocked for seg in segments)


def _doh_answers(hostname: str, record_type: str, timeout: float) -> list[str] | None:
    """Return rdata strings, or None if the lookup failed."""
    try:
        resp = requests.get(
            FAMILY_DOH_URL,
            params={"name": hostname, "type": record_type},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None

    answers = data.get("Answer") or []
    records: list[str] = []
    for ans in answers:
        if ans.get("type") not in (1, 28):  # A, AAAA
            continue
        rdata = ans.get("data")
        if rdata:
            records.append(rdata)
    return records


def _family_dns_sinkholed(hostname: str, timeout: float) -> bool | None:
    """True if family DNS sinkholes the host, False if it looks clean, None on error."""
    a_records = _doh_answers(hostname, "A", timeout)
    aaaa_records = _doh_answers(hostname, "AAAA", timeout)
    if a_records is None and aaaa_records is None:
        return None

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in (a_records or []) + (aaaa_records or []):
        try:
            ips.append(ipaddress.ip_address(raw.split("%")[0]))
        except ValueError:
            continue

    if not ips:
        return False
    return all(ip in _SINKHOLE for ip in ips)


def adult_content_reason(url: str, timeout: float) -> str | None:
    """Return a block reason, or None if the URL looks safe enough to fetch."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    host = _normalize_host(host)
    print("normalized host:", host)

    if _domain_blocked(host) or _path_blocked(url):
        return "Blocked as adult content"

    sinkholed = _family_dns_sinkholed(host, timeout)
    if sinkholed:
        return "Blocked by family DNS filter (adult or malware)"
    return None
