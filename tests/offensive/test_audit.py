"""Audit module tests — write, query, count."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from offensive import audit


@pytest.fixture()
def audit_db(tmp_path: Path) -> Path:
    return tmp_path / "audit.db"


def test_write_and_query_round_trip(audit_db: Path):
    audit.init_db(audit_db)
    eid = audit.write_entry(
        actor="alice",
        action="nmap.scan",
        target="127.0.0.1",
        params={"ports": "1-100"},
        exit_code=0,
        summary="ok",
        db_path=audit_db,
    )
    assert isinstance(eid, str) and len(eid) == 36  # UUID4

    rows = audit.query(audit.AuditQuery(limit=10), db_path=audit_db)
    assert len(rows) == 1
    assert rows[0].actor == "alice"
    assert rows[0].action == "nmap.scan"
    assert rows[0].target == "127.0.0.1"
    assert rows[0].params == {"ports": "1-100"}


def test_filters_by_action_and_target(audit_db: Path):
    audit.init_db(audit_db)
    audit.write_entry("alice", "nmap.scan", "127.0.0.1", {}, 0, "a", db_path=audit_db)
    audit.write_entry("alice", "sqlmap.scan", "127.0.0.1", {}, 0, "b", db_path=audit_db)
    audit.write_entry("bob",   "nmap.scan", "127.0.0.42", {}, 0, "c", db_path=audit_db)

    only_nmap = audit.query(audit.AuditQuery(action="nmap.scan"), db_path=audit_db)
    assert {r.actor for r in only_nmap} == {"alice", "bob"}
    only_target = audit.query(audit.AuditQuery(target="127.0.0.1"), db_path=audit_db)
    assert {r.action for r in only_target} == {"nmap.scan", "sqlmap.scan"}


def test_count_action_window(audit_db: Path):
    audit.init_db(audit_db)
    now = time.time()
    audit.write_entry("a", "x.test", "127.0.0.1", {}, 0, "1", db_path=audit_db)
    audit.write_entry("a", "x.test", "127.0.0.1", {}, 0, "2", db_path=audit_db)
    audit.write_entry("a", "x.test", "127.0.0.1", {}, 0, "3", db_path=audit_db)
    assert audit.count_action("x.test", since=now - 1, db_path=audit_db) == 3
    assert audit.count_action("x.test", since=now + 60, db_path=audit_db) == 0


def test_latest_returns_newest_first(audit_db: Path):
    audit.init_db(audit_db)
    audit.write_entry("a", "x.test", "127.0.0.1", {}, 0, "first",  db_path=audit_db)
    audit.write_entry("a", "x.test", "127.0.0.1", {}, 0, "second", db_path=audit_db)
    rows = audit.latest(limit=2, db_path=audit_db)
    assert [r.summary for r in rows] == ["second", "first"]


def test_default_db_path_respects_env(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("GUARDSCOPE_AUDIT_DB", str(tmp_path / "override.db"))
    assert audit.default_db_path() == tmp_path / "override.db"
