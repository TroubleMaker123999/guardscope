"""sqlmap wrapper — SQL injection detection on registered loopback web targets.

Defaults are tight: only ``--level=1`` / ``--risk=1`` is exposed, no OS shell
injection (``--os-shell``), and the output is captured for parsing rather than
written into the DB.
"""

from __future__ import annotations

import json
import shutil
import subprocess
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

DEFAULT_LEVEL = 1
DEFAULT_RISK = 1
DEFAULT_TIMEOUT = 180

# Flags that are NEVER forwarded regardless of caller (defense in depth).
_BLOCKED_FLAGS = {
    "--os-shell",  # would give an interactive shell on the target
    "--os-pwn",
    "--file-write",
    "--file-dest",
    "--sql-shell",
    "--eval",
    "--bind",  # port forwarding
}


def sqlmap_binary() -> str:
    path = shutil.which("sqlmap")
    if path is None:
        raise ScopeViolation(
            "sqlmap binary not found in PATH; install with `apt-get install sqlmap`"
        )
    return path


@dataclass
class SqlmapResult:
    target: str
    url: str
    command: List[str]
    log_path: Path
    summary: str
    injectable: bool


def _sanitize_extra(extra: List[str]) -> List[str]:
    sanitized: List[str] = []
    for arg in extra:
        if arg in _BLOCKED_FLAGS:
            raise ScopeViolation(
                f"sqlmap flag {arg!r} is forbidden by the offensive scope guard"
            )
        sanitized.append(arg)
    return sanitized


def run_sqlmap(
    target: str,
    url: str,
    *,
    level: int = DEFAULT_LEVEL,
    risk: int = DEFAULT_RISK,
    extra_args: Optional[List[str]] = None,
    out_dir: Path,
    actor: Optional[str] = None,
    audit_db: Optional[Path] = None,
    db_path: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> SqlmapResult:
    """Invoke sqlmap against a loopback URL.

    ``level`` is clamped to ``[1, 2]`` and ``risk`` to ``[1, 2]`` — these
    cover the safe banner/error-based and UNION/boolean tests without escalating
    to time-based blind or stacked queries by default.
    """

    if level < 1 or level > 2:
        raise ScopeViolation(f"sqlmap level must be 1 or 2, got {level}")
    if risk < 1 or risk > 2:
        raise ScopeViolation(f"sqlmap risk must be 1 or 2, got {risk}")

    host = resolve_target(target)
    run: AuthorizedRun = assert_authorized(
        host,
        action="sqlmap.scan",
        actor=actor,
        db_path=db_path,
        audit_db=audit_db,
    )

    extra_args = _sanitize_extra(list(extra_args or []))

    args: List[str] = [
        sqlmap_binary(),
        "-u", url,
        "--level", str(level),
        "--risk", str(risk),
        "--batch",                       # never prompt
        "--output-dir", str(out_dir),
        "--flush-session",
    ] + extra_args

    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"sqlmap-{run.actor}-{int(run.started_at)}.txt"

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
    log_path.write_text(
        stdout + "\n--- stderr ---\n" + stderr,
        encoding="utf-8",
        errors="replace",
    )
    summary = (
        f"sqlmap scanned {url} level={level} risk={risk}; exit={proc.returncode}; "
        f"log={log_path.name}"
    )
    injectable = "Parameter: " in proc.stdout and "appears to be" in proc.stdout
    record_completion(
        run,
        exit_code=proc.returncode,
        params={"url": url, "level": level, "risk": risk, "extra": extra_args},
        summary=summary,
        audit_db=audit_db,
    )
    return SqlmapResult(
        target=host,
        url=url,
        command=args,
        log_path=log_path,
        summary=summary,
        injectable=injectable,
    )
