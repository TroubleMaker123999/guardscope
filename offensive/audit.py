"""SQLite-backed audit log for the offensive module.

Every tool invocation routed through ``offensive.scope_guard`` writes a row
here. The schema is intentionally narrow — we record who/what/when/why, not
output data — so that the audit log stays small and is easy to search.

The DB file is ``offensive/audit.db`` (gitignored) by default; tests pass a
``db_path`` argument.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


# Use a thread-local connection so concurrent invocations don't trample each
# other when the CLI is exercised under load (e.g. parallel lab health checks).
# Stored as a (path, connection) tuple because sqlite3.Connection is a C type
# and does not accept arbitrary attribute assignment.
_tls = threading.local()


@dataclass
class AuditEntry:
    id: str
    timestamp: float
    actor: str
    action: str
    target: str
    params: Dict[str, Any]
    exit_code: Optional[int]
    summary: str


@dataclass
class AuditQuery:
    limit: int = 100
    action: Optional[str] = None
    target: Optional[str] = None
    since: Optional[float] = None


def default_db_path() -> Path:
    """Resolve the default audit DB path; honors AUDIT_DB env override."""

    override = os.environ.get("GUARDSCOPE_AUDIT_DB")
    if override:
        return Path(override)
    return Path(__file__).parent / "audit.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Create the audit table if it doesn't exist yet."""

    path = db_path or default_db_path()
    with _connect(path) as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id        TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                actor     TEXT NOT NULL,
                action    TEXT NOT NULL,
                target    TEXT NOT NULL,
                params    TEXT NOT NULL,
                exit_code INTEGER,
                summary   TEXT NOT NULL
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_target ON audit(target)")


@contextmanager
def _conn(db_path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    path = db_path or default_db_path()
    init_db(path)
    cached_path, cached_conn = getattr(_tls, "cache", (None, None))
    if cached_conn is None or cached_path != str(path):
        cached_conn = _connect(path)
        _tls.cache = (str(path), cached_conn)
    try:
        yield cached_conn
    except Exception:
        cached_conn.rollback()
        raise


def write_entry(
    actor: str,
    action: str,
    target: str,
    params: Dict[str, Any],
    exit_code: Optional[int],
    summary: str,
    db_path: Optional[Path] = None,
) -> str:
    """Append a single audit row and return its UUID."""

    entry_id = str(uuid.uuid4())
    with _conn(db_path) as c:
        c.execute(
            """
            INSERT INTO audit (id, timestamp, actor, action, target, params, exit_code, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                time.time(),
                actor,
                action,
                target,
                json.dumps(params, ensure_ascii=False, sort_keys=True),
                exit_code,
                summary,
            ),
        )
        c.commit()
    return entry_id


def query(query: AuditQuery, db_path: Optional[Path] = None) -> List[AuditEntry]:
    """Return audit rows matching the supplied filters, newest first."""

    clauses: List[str] = []
    args: List[Any] = []
    if query.action is not None:
        clauses.append("action = ?")
        args.append(query.action)
    if query.target is not None:
        clauses.append("target = ?")
        args.append(query.target)
    if query.since is not None:
        clauses.append("timestamp >= ?")
        args.append(query.since)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with _conn(db_path) as c:
        rows = c.execute(
            f"SELECT * FROM audit {where} ORDER BY timestamp DESC LIMIT ?",
            (*args, query.limit),
        ).fetchall()
    return [
        AuditEntry(
            id=r["id"],
            timestamp=r["timestamp"],
            actor=r["actor"],
            action=r["action"],
            target=r["target"],
            params=json.loads(r["params"]),
            exit_code=r["exit_code"],
            summary=r["summary"],
        )
        for r in rows
    ]


def count_action(action: str, since: float, db_path: Optional[Path] = None) -> int:
    """Used by ``scope_guard`` for per-action rate limiting."""

    with _conn(db_path) as c:
        row = c.execute(
            "SELECT COUNT(*) AS n FROM audit WHERE action = ? AND timestamp >= ?",
            (action, since),
        ).fetchone()
    return int(row["n"] or 0)


def latest(limit: int = 1, db_path: Optional[Path] = None) -> List[AuditEntry]:
    """Return the N most recent audit rows (across all actions)."""

    with _conn(db_path) as c:
        rows = c.execute(
            "SELECT * FROM audit ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        AuditEntry(
            id=r["id"],
            timestamp=r["timestamp"],
            actor=r["actor"],
            action=r["action"],
            target=r["target"],
            params=json.loads(r["params"]),
            exit_code=r["exit_code"],
            summary=r["summary"],
        )
        for r in rows
    ]
