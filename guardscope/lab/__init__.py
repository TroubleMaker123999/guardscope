"""Local lab registry and strict scope guard.

GuardScope refuses to perform any verification action against a host that is
not registered as a local lab target **and** resolves to ``127.0.0.1`` /
``::1`` / ``localhost``. The default safety gate rejects external hosts
outright.
"""

from .registry import Lab, LabRegistry
from .scope import (
    ScopeError,
    assert_in_scope,
    is_local_host,
    host_in_any_registered_lab,
)

__all__ = [
    "Lab",
    "LabRegistry",
    "ScopeError",
    "assert_in_scope",
    "is_local_host",
    "host_in_any_registered_lab",
]