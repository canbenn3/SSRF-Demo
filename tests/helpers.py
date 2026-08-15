"""Shared helpers for compose network-isolation tests."""

from __future__ import annotations

import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "--project-directory", str(ROOT)]

# Runs inside app containers (stdlib only). Prints one JSON object.
_PROBE = r"""
import json, socket, sys, urllib.error, urllib.request
host = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
out = {"dns": False, "http": False, "status": None, "body": "", "error": None}
try:
    socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    out["dns"] = True
except socket.gaierror as exc:
    out["error"] = f"dns: {exc}"
    print(json.dumps(out))
    raise SystemExit(0)
try:
    url = f"http://{host}:{port}/" if port != 80 else f"http://{host}/"
    with urllib.request.urlopen(url, timeout=5) as resp:
        out["http"] = True
        out["status"] = resp.status
        out["body"] = resp.read(512).decode("utf-8", "replace")
except Exception as exc:
    out["error"] = str(exc)
print(json.dumps(out))
"""


def compose(*args: str, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*COMPOSE, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


def probe_from_service(service: str, host: str, port: int = 80) -> dict:
    result = subprocess.run(
        [*COMPOSE, "exec", "-T", service, "python", "-c", _PROBE, host, str(port)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"probe on {service!r} for {host}:{port} failed "
            f"(exit {result.returncode}): {result.stderr or result.stdout}"
        )
    line = result.stdout.strip().splitlines()[-1]
    return json.loads(line)


def http_from_host(url: str, timeout: float = 8.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(2048).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read(2048).decode("utf-8", "replace") if exc.fp else ""
        return exc.code, body


def wait_http_ok(url: str, *, attempts: int = 20, delay: float = 1.0) -> tuple[int, str]:
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            status, body = http_from_host(url)
            if status < 500:
                return status, body
        except (urllib.error.URLError, TimeoutError, ConnectionError, socket.timeout) as exc:
            last_exc = exc
        time.sleep(delay)
    raise AssertionError(f"timed out waiting for {url}: {last_exc}")


def gitstub_host_port_bindings() -> dict:
    """Host-published ports for gitstub (empty means nothing is bound on localhost)."""
    cid = compose("ps", "-q", "gitstub").stdout.strip().splitlines()[0]
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", cid],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    raw = inspect.stdout.strip()
    if not raw or raw in {"null", "{}", "map[]"}:
        return {}
    return json.loads(raw)
