"""Network isolation for the local compose stack.

Requires the stack: `docker compose up --build`
Run: `pip install -r tests/requirements.txt && pytest tests/`
"""

from __future__ import annotations

import socket

import pytest

from tests.helpers import (
    gitstub_host_port_bindings,
    http_from_host,
    probe_from_service,
    wait_http_ok,
)

pytestmark = pytest.mark.usefixtures("compose_up")


def test_gitstub_reachable_from_web_curl_server():
    result = probe_from_service("web-curl-server", "gitstub")
    assert result["dns"] is True, result
    assert result["http"] is True, result
    assert result["status"] == 200, result
    assert "GitStub" in result["body"], result


def test_gitstub_not_resolvable_from_localhost():
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("gitstub", 80, proto=socket.IPPROTO_TCP)


def test_gitstub_has_no_published_ports():
    assert gitstub_host_port_bindings() == {}


def test_gitstub_not_routed_on_localhost_http():
    status, body = http_from_host("http://gitstub.localhost/")
    assert "GitStub" not in body
    assert status in {404, 503}


def test_gitstub_not_reachable_from_mock_website():
    result = probe_from_service("mock-website", "gitstub")
    assert result["dns"] is False, (
        "mock-website must not resolve gitstub via Docker DNS: " + str(result)
    )
    assert result["http"] is False, result


def test_curl_mock_and_ctfd_reachable_from_localhost():
    curl_status, curl_body = wait_http_ok("http://curl.localhost/")
    assert curl_status == 200
    assert "Secure Web cURL" in curl_body

    mock_status, mock_body = wait_http_ok("http://mock.localhost/")
    assert mock_status == 200
    assert "Hello World" in mock_body

    ctf_status, _ = wait_http_ok("http://ctf.localhost/")
    assert ctf_status < 500


def test_web_curl_server_cannot_resolve_mock_website_or_ctfd():
    mock = probe_from_service("web-curl-server", "mock-website")
    assert mock["dns"] is False, (
        "web-curl-server must not resolve mock-website; use http://mock.localhost "
        f"from the host instead: {mock}"
    )

    ctfd = probe_from_service("web-curl-server", "ctfd")
    assert ctfd["dns"] is False, (
        "web-curl-server must not resolve ctfd; use http://ctf.localhost "
        f"from the host instead: {ctfd}"
    )
