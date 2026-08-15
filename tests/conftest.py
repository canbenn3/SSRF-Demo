"""Pytest fixtures for compose network-isolation tests."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tests.helpers import compose


@pytest.fixture(scope="session")
def compose_up() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    try:
        result = compose("ps", "-q", check=False)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker compose is not available: {exc}")
    if result.returncode != 0 or not result.stdout.strip():
        pytest.skip(
            "docker compose stack is not running; start it with "
            "`docker compose up --build` from the repo root"
        )
