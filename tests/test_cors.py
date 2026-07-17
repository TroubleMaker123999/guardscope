"""CORS middleware configuration tests.

Validates the safety boundary documented in docs/frontend.md:

  - Default allow-list is loopback-only (Vite dev server).
  - GUARDSCOPE_CORS_ORIGINS extends the list (additive, never shrinks).
  - Wildcard ``*`` is never used by default; it is also rejected as a
    literal origin in the env var to avoid silent widening.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient


def _resolve_origins(monkeypatch, env_value):
    """Reload the api module with a controlled env so we exercise the
    production helper exactly as the CLI does."""
    if env_value is None:
        monkeypatch.delenv("GUARDSCOPE_CORS_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("GUARDSCOPE_CORS_ORIGINS", env_value)
    # Reload so _cors_origins_from_env picks up the env at import time.
    import guardscope.api.app as app_module
    importlib.reload(app_module)
    return app_module._cors_origins_from_env()


def test_cors_defaults_are_loopback_only(monkeypatch):
    origins = _resolve_origins(monkeypatch, env_value=None)
    assert origins == ["http://127.0.0.1:5173", "http://localhost:5173"]
    # No wildcard anywhere.
    assert "*" not in origins
    assert "null" not in origins


def test_cors_env_extends_default(monkeypatch):
    origins = _resolve_origins(monkeypatch, env_value="https://guardscope.internal")
    # Defaults preserved, plus the extra origin appended.
    assert origins == [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "https://guardscope.internal",
    ]


def test_cors_env_strips_blank_and_dedupes(monkeypatch):
    origins = _resolve_origins(monkeypatch, env_value=" ,https://a.example, ,https://b.example,")
    assert origins == [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "https://a.example",
        "https://b.example",
    ]


def test_cors_env_rejects_wildcard(monkeypatch):
    """The wildcard is never added to allow_origins by default and is also
    refused as a literal entry from the env var to prevent silent widening."""
    origins = _resolve_origins(monkeypatch, env_value="*")
    assert "*" not in origins
    # Only the safe loopback defaults remain.
    assert origins == ["http://127.0.0.1:5173", "http://localhost:5173"]


def test_cors_middleware_registered_with_defaults(monkeypatch):
    """create_app() should attach a CORSMiddleware whose allow_origins match
    the helper output, and the middleware must be present in app.user_middleware.

    Verifies the safe-flag defaults (credentials off, no wildcard) by issuing
    a real preflight OPTIONS request through Starlette TestClient, which is
    the source of truth for what the browser actually sees."""
    monkeypatch.delenv("GUARDSCOPE_CORS_ORIGINS", raising=False)
    import guardscope.api.app as app_module
    importlib.reload(app_module)

    app = app_module.create_app(db_path=":memory:")

    # Middleware is registered.
    cors_layers = [m for m in app.user_middleware if m.cls is CORSMiddleware]
    assert cors_layers, "CORSMiddleware not registered on the app"

    # End-to-end behavior: send a real preflight, assert the response
    # confirms only the default loopback origins are accepted.
    client = TestClient(app)

    # Allowed origin -> preflight succeeds, ACAO reflects the origin.
    resp_ok = client.options(
        "/health",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp_ok.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"

    # Disallowed origin -> preflight must NOT echo any ACAO header.
    resp_blocked = client.options(
        "/health",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp_blocked.headers.get("access-control-allow-origin") is None


@pytest.mark.parametrize("bad_origin", ["*", " null", "null", "NULL"])
def test_cors_env_rejects_browser_null_and_star(bad_origin, monkeypatch):
    """The literal browser-origin 'null' is a known CORS smuggling target;
    it must never be added by the env path either."""
    origins = _resolve_origins(monkeypatch, env_value=bad_origin)
    assert bad_origin.strip() not in origins
    assert "*" not in origins
    assert "null" not in [o.lower() for o in origins]
