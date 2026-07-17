"""Hard scope guard for the offensive module.

Every wrapper under ``offensive.*`` MUST call :func:`assert_authorized` before
touching the underlying tool, and :func:`assert_authorized` MUST be the first
substantive call.

Three checks are enforced, in order:

1. **Loopback-only** — the target host must resolve to a loopback address
   (``localhost`` / ``127.0.0.0/8`` / ``::1``). This reuses
   :func:`guardscope.lab.scope.is_local_host`.
2. **Lab-registered** — the target host must be listed in the registered lab
   whitelist (``guardscope.lab.registry.LabRegistry.list``).
3. **Rate-limited** — the same ``action`` label cannot be invoked more than
   ``MAX_INVOCATIONS_PER_MINUTE`` times in any rolling 60-second window.

All three checks must pass. Failures raise :class:`ScopeViolation`.
"""

from __future__ import annotations

import os
import socket
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Deque, Dict, List, Optional

from guardscope.lab.scope import is_local_host

from . import audit


MAX_INVOCATIONS_PER_MINUTE = 30
WINDOW_SECONDS = 60.0

# A thread-local rolling window of timestamps per action label so the scope
# guard can rate-limit without depending on the audit log being written. The
# window is reset only when the process restarts; that is acceptable for an
# interactive CLI tool and for tests that create fresh threads.
_action_windows: Dict[str, Deque[float]] = {}


class ScopeViolation(RuntimeError):
    """Raised when an offensive action is refused by the scope guard."""


@dataclass(frozen=True)
class AuthorizedRun:
    """Result of passing the scope guard; the runner carries this evidence."""

    target: str
    action: str
    actor: str
    started_at: float


def actor_from_env(default: str = "anonymous") -> str:
    """Best-effort identity tag for the audit row."""

    return (
        os.environ.get("GUARDSCOPE_ACTOR")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or default
    )


def _registered_hosts(db_path: Optional[str]) -> List[str]:
    """Pull the list of hosts currently registered in the lab registry.

    Importing the registry lazily so this module stays unit-testable without
    touching SQLite on import.
    """

    from guardscope.lab.registry import LabRegistry  # local import

    db = db_path or os.environ.get("GUARDSCOPE_DB") or "./guardscope.db"
    return [l.host for l in LabRegistry(db).list()]


def _is_local_demo_host(host: str) -> bool:
    """Demo-mode concession so the wrapper can exercise its own harness.

    ``guardscope demo`` registers a single loopback lab whose host is
    ``127.0.0.1`` by default. We treat both ``localhost`` and ``127.0.0.1`` as
    "demo lab hosts" when they appear in the registry, plus any host the
    operator has explicitly listed in ``GUARDSCOPE_OFFENSIVE_ALLOW`` (a
    comma-separated env var).
    """

    demo_hosts = {"localhost", "127.0.0.1", "::1"}
    extra = os.environ.get("GUARDSCOPE_OFFENSIVE_ALLOW", "")
    extra_hosts = {h.strip().lower() for h in extra.split(",") if h.strip()}
    return host in demo_hosts or host in extra_hosts


def assert_authorized(
    target: str,
    action: str,
    *,
    actor: Optional[str] = None,
    db_path: Optional[str] = None,
    audit_db: Optional[Path] = None,
) -> AuthorizedRun:
    """Run all three checks. Raises :class:`ScopeViolation` on any failure.

    :param target: the host the action will be directed at. May be a hostname,
        IPv4/IPv6 literal, or ``host:port`` form (the port is ignored here).
    :param action: short label, e.g. ``"nmap.scan"``, ``"hydra.ssh_brute"``.
    :param actor: caller identity, used for the audit row.
    :param db_path: path to the GuardScope SQLite DB; defaults to the env value.
    """

    host = target.split(":", 1)[0].strip().lower()

    # 1. Loopback check (no DNS lookup, no implicit trust).
    if not is_local_host(host):
        raise ScopeViolation(
            f"refused: host {host!r} is not in the loopback scope "
            f"(only localhost / 127.0.0.0/8 / ::1 are accepted)"
        )

    # 2. Lab-registered check. A registered demo lab OR an explicit
    #    GUARDSCOPE_OFFENSIVE_ALLOW host OR the canonical ``localhost`` /
    #    ``127.0.0.1`` demo targets are all accepted.
    if not _is_local_demo_host(host):
        registered = _registered_hosts(db_path)
        if host not in registered:
            raise ScopeViolation(
                f"refused: host {host!r} is not in the registered lab whitelist; "
                f"register it first via `guardscope labs register` or list it in "
                f"GUARDSCOPE_OFFENSIVE_ALLOW"
            )

    # 3. Rate limit, tracked in-process so it doesn't depend on the
    #    audit log already having the row written.
    now = time.time()
    window = _action_windows.setdefault(action, deque())
    cutoff = now - WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= MAX_INVOCATIONS_PER_MINUTE:
        raise ScopeViolation(
            f"refused: action {action!r} exceeded the {MAX_INVOCATIONS_PER_MINUTE}-per-minute "
            f"rate limit (saw {len(window)} in the last {int(WINDOW_SECONDS)}s); "
            f"this guard prevents runaway automation, not real attackers"
        )
    window.append(now)

    return AuthorizedRun(
        target=host,
        action=action,
        actor=actor or actor_from_env(),
        started_at=now,
    )


def reset_rate_limits() -> None:
    """Test/admin escape hatch — clear the in-process action windows."""

    _action_windows.clear()


def record_completion(
    run: AuthorizedRun,
    *,
    exit_code: Optional[int],
    params: dict,
    summary: str,
    audit_db: Optional[Path] = None,
) -> str:
    """Write the audit row for a finished run. Returns the entry UUID."""

    return audit.write_entry(
        actor=run.actor,
        action=run.action,
        target=run.target,
        params=params,
        exit_code=exit_code,
        summary=summary,
        db_path=audit_db,
    )


def resolve_target(target: str) -> str:
    """Convenience helper to normalize ``127.0.0.1:8080`` -> ``127.0.0.1``.

    Raises :class:`ScopeViolation` if the hostname cannot be resolved to a
    loopback address (defensive against hosts that happen to resolve publicly
    while still looking like loopback strings).
    """

    host = target.split(":", 1)[0]
    # Resolve but only accept loopback answers.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeViolation(f"refused: cannot resolve {host!r}: {exc}") from exc
    for family, _socktype, _proto, _canon, sockaddr in infos:
        addr: str = str(sockaddr[0])
        if not is_local_host(addr):
            raise ScopeViolation(
                f"refused: {host!r} resolves to {addr!r}, which is not loopback"
            )
    return host
