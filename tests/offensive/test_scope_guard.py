"""Scope guard tests — three checks must each be enforced."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from offensive.audit import default_db_path
from offensive.scope_guard import (
    ScopeViolation,
    assert_authorized,
    resolve_target,
)


@pytest.fixture(autouse=True)
def _isolated_audit(tmp_path, monkeypatch):
    """Each test gets its own audit DB to avoid interference."""

    audit_db = tmp_path / "audit.db"
    monkeypatch.setenv("GUARDSCOPE_AUDIT_DB", str(audit_db))
    # Reset in-process rate limit windows so tests do not bleed quota into each other.
    from offensive.scope_guard import reset_rate_limits
    reset_rate_limits()
    yield audit_db


def test_loopback_host_is_accepted(_isolated_audit):
    run = assert_authorized("127.0.0.1", action="nmap.scan")
    assert run.target == "127.0.0.1"
    assert run.action == "nmap.scan"


@pytest.mark.parametrize(
    "bad_host",
    [
        "8.8.8.8",
        "1.1.1.1",
        "example.com",
        "10.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "192.168.1.1",
    ],
)
def test_non_loopback_is_refused(bad_host, _isolated_audit):
    with pytest.raises(ScopeViolation, match="not in the loopback scope"):
        assert_authorized(bad_host, action="nmap.scan")


def test_noncanonical_loopback_still_requires_registration(_isolated_audit, tmp_path):
    """``127.0.0.42`` is loopback (passes check 1) but is not in the
    canonical demo set, so it must still be either registered or in the
    ``GUARDSCOPE_OFFENSIVE_ALLOW`` list."""
    db = tmp_path / "empty.db"
    with pytest.raises(ScopeViolation, match="registered lab whitelist"):
        assert_authorized("127.0.0.42", action="nmap.scan", db_path=str(db))


def test_target_must_be_registered_with_demo_host(_isolated_audit, tmp_path):
    """When the demo lab (localhost) is registered, it is accepted."""
    db = tmp_path / "demo.db"
    from guardscope.core.db import init_db
    from guardscope.lab.registry import LabRegistry
    init_db(str(db))
    LabRegistry(str(db)).register("demo-nginx", "127.0.0.1", 8080, "demo")
    run = assert_authorized("localhost", action="nmap.scan", db_path=str(db))
    assert run.target == "localhost"


def test_explicit_overrides_open_extra_loopback_hosts(_isolated_audit, tmp_path, monkeypatch):
    db = tmp_path / "allowlist.db"
    from guardscope.core.db import init_db
    init_db(str(db))
    monkeypatch.setenv("GUARDSCOPE_OFFENSIVE_ALLOW", "127.0.0.42")
    # The override list grants the operator an extra host without a registry row.
    assert_authorized("127.0.0.42", action="nmap.scan", db_path=str(db))


def test_rate_limit_caps_invocation_frequency(_isolated_audit, tmp_path):
    from offensive.scope_guard import MAX_INVOCATIONS_PER_MINUTE
    db = tmp_path / "ratelimit.db"
    from guardscope.core.db import init_db
    init_db(str(db))
    # Burn through the per-action quota in a tight loop.
    for _ in range(MAX_INVOCATIONS_PER_MINUTE):
        assert_authorized("127.0.0.1", action="rate.test", db_path=str(db))
    with pytest.raises(ScopeViolation, match="rate limit"):
        assert_authorized("127.0.0.1", action="rate.test", db_path=str(db))


def test_resolve_target_rejects_public_dns(_isolated_audit):
    """If a hostname accidentally resolves to a non-loopback address, refuse."""
    import socket as _socket

    real_getaddrinfo = _socket.getaddrinfo

    def fake(name, *args, **kwargs):
        # Pretend the operator-typed "localhost" resolved to a public address.
        return [(2, 1, 6, "", ("8.8.8.8", 0))]

    with patch.object(_socket, "getaddrinfo", side_effect=fake):
        with pytest.raises(ScopeViolation, match="not loopback"):
            resolve_target("localhost")


def test_resolve_target_unknown_hostname(_isolated_audit):
    with pytest.raises(ScopeViolation, match="cannot resolve"):
        resolve_target("definitely-not-a-real-host.invalid")


def test_target_with_port_is_normalized(_isolated_audit):
    run = assert_authorized("127.0.0.1:8080", action="nmap.scan")
    assert run.target == "127.0.0.1"
