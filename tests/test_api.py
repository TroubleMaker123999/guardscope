"""API tests using FastAPI TestClient."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardscope.api.app import create_app


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    db = str(tmp_path / "api.db")
    app = create_app(db)
    return TestClient(app)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_labs_register_and_list(client):
    r = client.post("/labs", json={"name": "demo", "host": "127.0.0.1", "port": 8080, "description": "demo lab"})
    assert r.status_code == 200, r.text
    r = client.get("/labs")
    assert r.status_code == 200
    assert any(l["name"] == "demo" for l in r.json())


def test_labs_rejects_external_host(client):
    r = client.post("/labs", json={"name": "evil", "host": "example.com", "port": 80})
    assert r.status_code == 400


def test_scope_check_accepts_loopback(client):
    client.post("/labs", json={"name": "demo", "host": "127.0.0.1", "port": 8080})
    r = client.get("/scope/check", params={"host": "127.0.0.1"})
    assert r.status_code == 200
    assert r.json()["in_scope"] is True


def test_scope_check_rejects_public(client):
    r = client.get("/scope/check", params={"host": "example.com"})
    assert r.status_code == 400
    assert "not in the local lab scope" in r.json()["reason"]


def test_create_and_get_finding(client):
    payload = {
        "title": "Test high finding",
        "description": "demo",
        "severity": "high",
        "confidence": "high",
        "cvss": 7.5,
        "cwe": ["CWE-79"],
        "source": "manual",
        "asset": "demo",
        "evidence": "x",
        "remediation": "fix it",
    }
    r = client.post("/findings", json=payload)
    assert r.status_code == 201, r.text
    fid = r.json()["id"]
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    assert r.json()["title"] == "Test high finding"


def test_findings_list_filtered(client):
    client.post(
        "/findings",
        json={"title": "low", "severity": "low", "source": "manual"},
    )
    client.post(
        "/findings",
        json={"title": "high", "severity": "high", "source": "manual"},
    )
    r = client.get("/findings", params={"severity": "high"})
    assert r.status_code == 200
    titles = [f["title"] for f in r.json()]
    assert "high" in titles and "low" not in titles


def test_delete_finding(client):
    r = client.post("/findings", json={"title": "x", "severity": "low"})
    fid = r.json()["id"]
    r = client.delete(f"/findings/{fid}")
    assert r.status_code == 200
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 404


def test_import_via_json_body(client, nmap_text):
    r = client.post(
        "/import",
        json={"source": "nmap", "text": nmap_text},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["parser"] == "nmap"
    assert data["imported"] >= 2
    r = client.get("/findings", params={"source": "nmap"})
    assert r.status_code == 200
    assert len(r.json()) >= 2


def test_import_via_multipart(client, fixtures_dir):
    with open(fixtures_dir / "zap_sample.json", "rb") as f:
        r = client.post(
            "/import",
            files={"file": ("zap.json", f, "application/json")},
        )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["parser"] == "zap"
    assert data["imported"] == 2


def test_report_markdown(client, zap_text):
    client.post("/import", json={"source": "zap", "text": zap_text})
    r = client.post("/report", params={"format": "markdown"})
    assert r.status_code == 200
    assert "GuardScope Report" in r.json()["body"]


def test_report_html(client, zap_text):
    client.post("/import", json={"source": "zap", "text": zap_text})
    r = client.post("/report", params={"format": "html"})
    assert r.status_code == 200
    body = r.json()["body"]
    assert "<html" in body.lower()


def test_report_sarif(client, zap_text):
    client.post("/import", json={"source": "zap", "text": zap_text})
    r = client.post("/report", params={"format": "sarif"})
    assert r.status_code == 200
    body = json.loads(r.json()["body"])
    assert body["version"] == "2.1.0"
    assert body["runs"][0]["results"]


def test_report_raw(client, zap_text):
    client.post("/import", json={"source": "zap", "text": zap_text})
    r = client.get("/report/raw", params={"format": "html"})
    assert r.status_code == 200
    assert "<html" in r.text.lower()


def test_cors_allows_loopback_frontend(client):
    r = client.get(
        "/health",
        headers={"Origin": "http://127.0.0.1:5173"},
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"


def test_cors_allows_localhost_frontend(client):
    r = client.get(
        "/health",
        headers={"Origin": "http://localhost:5173"},
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_blocks_unknown_origin(client):
    r = client.get(
        "/health",
        headers={"Origin": "https://evil.example"},
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") is None


def test_cors_preflight_allowed_methods(client):
    r = client.options(
        "/findings",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert r.status_code in (200, 204)
    allow_methods = r.headers.get("access-control-allow-methods", "")
    for verb in ("GET", "POST"):
        assert verb in allow_methods.upper()


def test_cors_origins_default_loopback(monkeypatch):
    monkeypatch.delenv("GUARDSCOPE_CORS_ORIGINS", raising=False)
    from guardscope.api.app import _cors_origins_from_env

    origins = _cors_origins_from_env()
    assert "http://127.0.0.1:5173" in origins
    assert "http://localhost:5173" in origins
    # No wildcard by default.
    assert "*" not in origins


def test_cors_origins_env_override_extends(monkeypatch):
    monkeypatch.setenv("GUARDSCOPE_CORS_ORIGINS", "https://guardscope.local,http://10.0.0.5:5173")
    from guardscope.api.app import _cors_origins_from_env

    origins = _cors_origins_from_env()
    # Defaults preserved.
    assert "http://127.0.0.1:5173" in origins
    assert "http://localhost:5173" in origins
    # Extra allowed.
    assert "https://guardscope.local" in origins
    assert "http://10.0.0.5:5173" in origins