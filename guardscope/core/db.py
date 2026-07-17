"""SQLAlchemy 2 ORM persistence.

Provides:

* :class:`FindingORM` — persistent form of :class:`Finding`.
* :class:`EvidenceORM` — raw evidence snippets.
* :class:`AuditORM`   — append-only audit log.
* :func:`init_db`     — create tables.
* :func:`session_scope` — context-managed session.
* :func:`save_findings` — upsert a list of findings (by fingerprint).
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable, Iterator, List, Sequence

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

from .fingerprint import fingerprint_finding
from .models import AuditRecord, EvidenceRecord, Finding


class Base(DeclarativeBase):
    pass


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    cwe: Mapped[str] = mapped_column(Text, default="")  # JSON list
    owasp: Mapped[str] = mapped_column(Text, default="")  # JSON list
    source: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    asset: Mapped[str] = mapped_column(String(512), default="", index=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    evidence_records: Mapped[List["EvidenceORM"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class EvidenceORM(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(64), default="")
    snippet: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    finding: Mapped[FindingORM] = relationship(back_populates="evidence_records")


class AuditORM(Base):
    __tablename__ = "audit"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def make_engine(db_path: str):
    """Create a SQLAlchemy engine for the given SQLite path."""

    url = f"sqlite:///{db_path}" if db_path != ":memory:" else "sqlite:///:memory:"
    return create_engine(url, future=True, echo=False)


def init_db(db_path: str) -> None:
    """Create all tables for a fresh database."""

    engine = make_engine(db_path)
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(db_path: str) -> Iterator[Session]:
    """Yield a SQLAlchemy session inside a transaction."""

    engine = make_engine(db_path)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def _finding_to_orm(f: Finding) -> FindingORM:
    if not f.fingerprint:
        fingerprint_finding(f)
    return FindingORM(
        id=f.id,
        fingerprint=f.fingerprint,
        title=f.title,
        description=f.description,
        severity=f.severity.value,
        confidence=f.confidence.value,
        cvss=f.cvss,
        cwe=json.dumps(f.cwe),
        owasp=json.dumps(f.owasp),
        source=f.source,
        asset=f.asset,
        evidence=f.evidence,
        remediation=f.remediation,
        created_at=f.created_at,
        updated_at=f.updated_at,
    )


def save_findings(db_path: str, findings: Sequence[Finding]) -> List[Finding]:
    """Upsert findings by fingerprint. Returns the persisted findings."""

    persisted: List[Finding] = []
    with session_scope(db_path) as s:
        for f in findings:
            if not f.fingerprint:
                fingerprint_finding(f)
            existing = s.execute(
                select(FindingORM).where(FindingORM.fingerprint == f.fingerprint)
            ).scalar_one_or_none()
            if existing is not None:
                # Refresh existing with new info; never replace the id.
                existing.title = f.title or existing.title
                existing.description = f.description or existing.description
                existing.severity = f.severity.value
                existing.confidence = f.confidence.value
                existing.cvss = f.cvss or existing.cvss
                existing.cwe = json.dumps(f.cwe) or existing.cwe
                existing.owasp = json.dumps(f.owasp) or existing.owasp
                existing.source = f.source or existing.source
                existing.asset = f.asset or existing.asset
                existing.evidence = f.evidence or existing.evidence
                existing.remediation = f.remediation or existing.remediation
                existing.updated_at = datetime.now(timezone.utc)
                if f.evidence:
                    s.add(
                        EvidenceORM(
                            id=str(__import__("uuid").uuid4()),
                            finding_id=existing.id,
                            source=f.source,
                            snippet=f.evidence,
                        )
                    )
                # Return a copy reflecting the merged record.
                f2 = Finding.model_validate(existing_to_dict(existing))
                persisted.append(f2)
            else:
                orm_obj = _finding_to_orm(f)
                s.add(orm_obj)
                if f.evidence:
                    s.add(
                        EvidenceORM(
                            id=str(__import__("uuid").uuid4()),
                            finding_id=orm_obj.id,
                            source=f.source,
                            snippet=f.evidence,
                        )
                    )
                persisted.append(f)
        # Audit entry.
        s.add(
            AuditORM(
                id=str(__import__("uuid").uuid4()),
                event="import",
                payload=json.dumps({"count": len(findings)}),
            )
        )
    return persisted


def existing_to_dict(o: FindingORM) -> dict:
    return {
        "id": o.id,
        "fingerprint": o.fingerprint,
        "title": o.title,
        "description": o.description,
        "severity": o.severity,
        "confidence": o.confidence,
        "cvss": o.cvss,
        "cwe": json.loads(o.cwe or "[]"),
        "owasp": json.loads(o.owasp or "[]"),
        "source": o.source,
        "asset": o.asset,
        "evidence": o.evidence,
        "remediation": o.remediation,
        "created_at": o.created_at,
        "updated_at": o.updated_at,
    }


def list_findings(db_path: str, *, severity: str | None = None, source: str | None = None) -> List[Finding]:
    """Return all findings, optionally filtered by severity/source."""

    with session_scope(db_path) as s:
        q = select(FindingORM)
        if severity:
            q = q.where(FindingORM.severity == severity)
        if source:
            q = q.where(FindingORM.source == source)
        rows = s.execute(q).scalars().all()
        return [Finding.model_validate(existing_to_dict(r)) for r in rows]


def get_finding(db_path: str, finding_id: str) -> Finding | None:
    with session_scope(db_path) as s:
        row = s.get(FindingORM, finding_id)
        if row is None:
            return None
        return Finding.model_validate(existing_to_dict(row))


def delete_finding(db_path: str, finding_id: str) -> bool:
    with session_scope(db_path) as s:
        row = s.get(FindingORM, finding_id)
        if row is None:
            return False
        s.delete(row)
        return True


def list_evidence(db_path: str, finding_id: str) -> List[EvidenceRecord]:
    with session_scope(db_path) as s:
        rows = s.execute(select(EvidenceORM).where(EvidenceORM.finding_id == finding_id)).scalars().all()
        return [
            EvidenceRecord(id=r.id, finding_id=r.finding_id, source=r.source, snippet=r.snippet, created_at=r.created_at)
            for r in rows
        ]


def append_audit(db_path: str, event: str, payload: str = "") -> AuditRecord:
    with session_scope(db_path) as s:
        rec = AuditORM(id=str(__import__("uuid").uuid4()), event=event, payload=payload)
        s.add(rec)
        s.flush()
        return AuditRecord(id=rec.id, event=rec.event, payload=rec.payload, created_at=rec.created_at)


__all__ = [
    "Base",
    "FindingORM",
    "EvidenceORM",
    "AuditORM",
    "init_db",
    "session_scope",
    "save_findings",
    "list_findings",
    "get_finding",
    "delete_finding",
    "list_evidence",
    "append_audit",
]