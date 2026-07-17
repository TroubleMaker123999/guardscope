"""HTTP API tests for the offensive module.

We exercise the FastAPI TestClient against :func:`offensive.api.router` with
an in-memory audit DB so we never read real attack outputs from disk. The
external binaries (nmap / hydra / sqlmap / nuclei) are not actually invoked —
scope-guard refusal paths fire before any subprocess is launched, and the
happy paths are covered separately in ``test_runners.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from offensive import audit


@pytest.fixture()
def audit_db(tmp_path: Path, monkeypatch) -> Path:
    """Redirect audit writes to a per-test SQLite file."""

    path = tmp_path / "audit.db"
    monkeypatch.setenv("GUARDSCOPE_AUDIT_DB", str(path))
    audit.init_db(path)
    return path


@pytest.fixture()
def client(audit_db) -> TestClient:
    """Build a minimal FastAPI app that mounts only the offensive router."""

    from offensive.api import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# availability + labs
# ---------------------------------------------------------------------------


def test_availability_reports_installed_tools(client):
    res = client.get("/offensive/availability")
    assert res.status_code == 200
    body = res.json()
    # At minimum nmap / hydra / sqlmap should report installed in this env.
    assert body["nmap"] is True
    assert body["hydra"] is True
    assert body["sqlmap"] is True
    # Nuclei is optional and was not installed in this test environment.
    assert "nuclei" in body


def test_labs_returns_catalog(client):
    res = client.get("/offensive/labs")
    assert res.status_code == 200
    body = res.json()
    assert isinstance(body, list)
    assert any(t["key"] == "juice-shop" for t in body)
    # Every entry is loopback.
    for t in body:
        assert t["host"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# Scan / brute / sqli — scope-guard refusal paths before any subprocess
# ---------------------------------------------------------------------------


def test_scan_refuses_non_loopback(client):
    res = client.post(
        "/offensive/scan",
        json={"target": "8.8.8.8", "ports": "1-100", "scan_type": "-sV"},
    )
    assert res.status_code == 400
    assert "loopback" in res.json()["detail"].lower()


def test_scan_refuses_stealth_scan_type(client):
    res = client.post(
        "/offensive/scan",
        json={"target": "127.0.0.1", "scan_type": "-sS"},
    )
    assert res.status_code == 400
    assert "scan_type" in res.json()["detail"]


def test_brute_refuses_unknown_service(client):
    res = client.post(
        "/offensive/brute",
        json={
            "target": "127.0.0.1",
            "service": "telnet",
            "username": "root",
            "wordlist_path": "/etc/hostname",
        },
    )
    assert res.status_code == 400
    assert "service" in res.json()["detail"].lower()


def test_sqli_refuses_out_of_range_level(client):
    res = client.post(
        "/offensive/sqli",
        json={"target": "127.0.0.1", "url": "http://127.0.0.1:3000/", "level": 5},
    )
    assert res.status_code == 400
    assert "level" in res.json()["detail"].lower()


def test_nuclei_returns_412_when_not_installed(client):
    with patch("offensive.api.nuclei_available", return_value=False):
        res = client.post(
            "/offensive/nuclei",
            json={"target": "127.0.0.1", "url": "http://127.0.0.1:3000/"},
        )
    assert res.status_code == 412


# ---------------------------------------------------------------------------
# runs — reads from the audit log
# ---------------------------------------------------------------------------


def test_runs_lists_audit_entries(client, audit_db):
    # Seed a fake offensive + a non-offensive audit entry.
    audit.write_entry("alice", "nmap.scan", "127.0.0.1", {}, 0, "ok", db_path=audit_db)
    audit.write_entry("alice", "hydra.ssh_brute", "127.0.0.1", {}, 0, "ok", db_path=audit_db)
    audit.write_entry(
        "alice", "manual.create", "127.0.0.1", {}, 0, "unrelated", db_path=audit_db
    )
    res = client.get("/offensive/runs")
    assert res.status_code == 200
    body = res.json()
    actions = {row["action"] for row in body}
    assert "nmap.scan" in actions
    assert "hydra.ssh_brute" in actions
    assert "manual.create" not in actions  # filtered out


def test_runs_caps_limit(client):
    res = client.get("/offensive/runs?limit=9999")
    assert res.status_code == 200  # capped silently at 500
    assert isinstance(res.json(), list)


def test_runs_handles_empty_audit(client, audit_db):
    res = client.get("/offensive/runs")
    assert res.status_code == 200
    assert res.json() == []
