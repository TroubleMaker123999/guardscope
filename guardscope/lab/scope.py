"""Strict scope guard.

The single choke point for any verification action. Refuses anything that
isn't ``localhost`` / ``127.0.0.1`` / ``::1`` by default, and additionally
requires the host to appear in a registered lab (if a registry is supplied).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Optional


class ScopeError(Exception):
    """Raised when a host is not within the local-lab scope."""


def is_local_host(host: str) -> bool:
    """Return True if ``host`` is ``localhost``, ``127.0.0.1``, or ``::1``."""

    if host is None:
        return False
    h = str(host).strip().lower()
    if h in {"localhost", "127.0.0.1", "::1", "[::1]"}:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback
    except ValueError:
        # Try DNS resolution as a last resort; refuse if it doesn't loop back.
        try:
            infos = socket.getaddrinfo(h, None)
        except socket.gaierror:
            return False
        for info in infos:
            sockaddr = info[4]
            ip = sockaddr[0]
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    return True
            except ValueError:
                continue
        return False


def host_in_any_registered_lab(host: str, registered_hosts: Iterable[str]) -> bool:
    h = (host or "").strip().lower()
    return any(h == r.strip().lower() for r in registered_hosts)


def assert_in_scope(host: str, *, registered_hosts: Optional[Iterable[str]] = None) -> str:
    """Validate that ``host`` may be the target of a verification action.

    Raises :class:`ScopeError` if not. Returns the normalized host on success.
    """

    if not host:
        raise ScopeError("refused: empty host")
    if not is_local_host(host):
        raise ScopeError(
            f"refused: host '{host}' is not in the local lab scope (must be localhost / 127.0.0.1 / ::1)"
        )
    if registered_hosts is not None and not host_in_any_registered_lab(host, registered_hosts):
        raise ScopeError(f"refused: host '{host}' is local but is not registered as a lab target")
    return host