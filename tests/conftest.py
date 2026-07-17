"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def nmap_text():
    return load("nmap_sample.xml")


@pytest.fixture
def zap_text():
    return load("zap_sample.json")


@pytest.fixture
def sarif_text():
    return load("sarif_sample.json")


@pytest.fixture
def bandit_text():
    return load("bandit_sample.json")


@pytest.fixture
def semgrep_text():
    return load("semgrep_sample.json")


@pytest.fixture
def trivy_text():
    return load("trivy_sample.json")


@pytest.fixture
def pipaudit_text():
    return load("pipaudit_sample.json")