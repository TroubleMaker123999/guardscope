"""Scope guard tests."""

import pytest

from guardscope.lab.scope import ScopeError, assert_in_scope, is_local_host


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "127.0.0.42"])
def test_is_local_host_true(host):
    assert is_local_host(host) is True


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "10.0.0.1", "169.254.169.254"])
def test_is_local_host_false(host):
    assert is_local_host(host) is False


def test_assert_in_scope_accepts_loopback():
    assert assert_in_scope("127.0.0.1") == "127.0.0.1"


def test_assert_in_scope_rejects_public():
    with pytest.raises(ScopeError):
        assert_in_scope("example.com")


def test_assert_in_scope_requires_registration_when_provided():
    with pytest.raises(ScopeError):
        assert_in_scope("127.0.0.1", registered_hosts=["10.0.0.1"])


def test_assert_in_scope_accepts_registered():
    out = assert_in_scope("127.0.0.1", registered_hosts=["127.0.0.1"])
    assert out == "127.0.0.1"


def test_assert_in_scope_rejects_empty():
    with pytest.raises(ScopeError):
        assert_in_scope("")


def test_lab_registry_refuses_external(tmp_path):
    from guardscope.lab.registry import LabRegistry

    reg = LabRegistry(str(tmp_path / "lab.db"))
    with pytest.raises(Exception):
        reg.register("evil", "example.com", 80)
    # Local host should be allowed.
    lab = reg.register("ok", "127.0.0.1", 8080)
    assert lab.host == "127.0.0.1"
    assert any(l.name == "ok" for l in reg.list())
    assert reg.remove("ok") is True
    assert reg.remove("ok") is False