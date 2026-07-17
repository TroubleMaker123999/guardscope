"""Hydra wrapper — online credential testing on registered loopback services.

Hard constraints:

  * Target must be a registered loopback host (enforced by scope_guard).
  * The password list must be a local file path; ``-p <inline>`` and
    default wordlists shipped with Hydra are NOT supported inline. By default
    we also refuse to use ``rockyou.txt`` from apt packages — the operator
    must explicitly opt in by setting ``HYDRA_ALLOW_ROCKYOU=1``.
  * A short per-service throttle (default 4 attempts/s) is applied.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .scope_guard import (
    AuthorizedRun,
    ScopeViolation,
    assert_authorized,
    record_completion,
    resolve_target,
)

ALLOWED_SERVICES = {"ssh", "http-get", "http-post", "ftp", "mysql", "postgres", "rdp"}
DEFAULT_THROTTLE = 4  # attempts per second; below this is broadly safe

ROCKYOU_HINT = "/usr/share/wordlists/rockyou.txt"


def hydra_binary() -> str:
    path = shutil.which("hydra")
    if path is None:
        raise ScopeViolation(
            "hydra binary not found in PATH; install with `apt-get install hydra`"
        )
    return path


@dataclass
class HydraResult:
    target: str
    service: str
    command: List[str]
    stdout_path: Path
    summary: str


def run_bruteforce(
    target: str,
    service: str,
    *,
    username: str,
    wordlist: Path,
    port: Optional[int] = None,
    throttle: int = DEFAULT_THROTTLE,
    out_dir: Path,
    actor: Optional[str] = None,
    audit_db: Optional[Path] = None,
    db_path: Optional[str] = None,
    timeout: int = 180,
) -> HydraResult:
    """Run an online credential test against a loopback service.

    ``wordlist`` MUST be a local file. ``service`` must be one of
    :data:`ALLOWED_SERVICES` (HTTP and SSH only by default — RDP/MySQL are
    listed for completeness but operators should think twice).
    """

    if service not in ALLOWED_SERVICES:
        raise ScopeViolation(
            f"service {service!r} not in allowlist {sorted(ALLOWED_SERVICES)}"
        )
    wordlist_path = Path(wordlist).expanduser().resolve()
    if not wordlist_path.is_file():
        raise ScopeViolation(f"wordlist {wordlist_path} is not a regular file")
    if wordlist_path == Path(ROCKYOU_HINT).resolve():
        if os.environ.get("HYDRA_ALLOW_ROCKYOU") != "1":
            raise ScopeViolation(
                f"refusing to use {ROCKYOU_HINT} without HYDRA_ALLOW_ROCKYOU=1; "
                f"generate a smaller local test wordlist instead"
            )

    host = resolve_target(target)
    run: AuthorizedRun = assert_authorized(
        host,
        action=f"hydra.{service}",
        actor=actor,
        db_path=db_path,
        audit_db=audit_db,
    )

    args: List[str] = [
        hydra_binary(),
        "-t",
        str(throttle),
        "-l",
        username,
        "-P",
        str(wordlist_path),
        "-f",  # stop on first valid pair
        service,
        host,
    ]
    if port is not None:
        args[1:1] = ["-s", str(port)]

    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"hydra-{service}-{run.actor}-{int(run.started_at)}.txt"

    started = time.time()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        stdout = proc.stdout
        stderr = proc.stderr
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stdout_path.write_text(stdout + "\n--- stderr ---\n" + stderr,
                               encoding="utf-8", errors="replace")
        exit_code = proc.returncode
        elapsed = time.time() - started
        hits = sum(1 for line in stdout.splitlines() if "[" in line and "]:" in line)
        summary = (
            f"hydra tested {service} on {host} as {username}; "
            f"exit={exit_code}; hits={hits}; elapsed={elapsed:.1f}s"
        )
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text("", encoding="utf-8")
        exit_code = -1
        summary = f"hydra timed out after {timeout}s on {service}://{host}"
        record_completion(
            run,
            exit_code=exit_code,
            params={"service": service, "username": username, "wordlist": str(wordlist_path), "throttle": throttle},
            summary=summary,
            audit_db=audit_db,
        )
        raise ScopeViolation(summary) from exc

    record_completion(
        run,
        exit_code=exit_code,
        params={"service": service, "username": username, "wordlist": str(wordlist_path), "throttle": throttle},
        summary=summary,
        audit_db=audit_db,
    )
    return HydraResult(target=host, service=service, command=args,
                      stdout_path=stdout_path, summary=summary)
