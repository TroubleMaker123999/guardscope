"""In-process lab registry (SQLite-backed optional).

Labs are stored in the same SQLite database as findings so a single ``--db``
flag gives you the full picture. The default policy is strict: only
``localhost`` / ``127.0.0.1`` / ``::1`` may be registered.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from sqlalchemy import Column, DateTime, String, Text, select

from ..core.db import Base, session_scope, make_engine
from .scope import is_local_host, ScopeError


@dataclass
class Lab:
    id: str
    name: str
    host: str
    port: int
    description: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class LabORM(Base):
    __tablename__ = "labs"

    id: str = Column(String(64), primary_key=True)
    name: str = Column(String(128), unique=True)
    host: str = Column(String(255), index=True)
    port: int = Column(String(8))  # SQLite affinity — store as string-safe int
    description: str = Column(Text, default="")
    created_at: str = Column(String(64), default="")


class LabRegistry:
    """SQLite-backed lab registry. Refuses non-localhost hosts."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure tables exist.
        engine = make_engine(db_path)
        Base.metadata.create_all(engine)

    def register(self, name: str, host: str, port: int, description: str = "") -> Lab:
        if not is_local_host(host):
            raise ScopeError(f"refused: host '{host}' is not in the local lab scope (must be localhost / 127.0.0.1 / ::1)")
        lab_id = str(uuid.uuid4())
        with session_scope(self.db_path) as s:
            existing = s.execute(select(LabORM).where(LabORM.name == name)).scalar_one_or_none()
            if existing is not None:
                # Update in place.
                existing.host = host
                existing.port = int(port)
                existing.description = description
                return Lab(
                    id=existing.id,
                    name=existing.name,
                    host=existing.host,
                    port=int(existing.port),
                    description=existing.description,
                    created_at=existing.created_at,
                )
            lab = LabORM(
                id=lab_id,
                name=name,
                host=host,
                port=int(port),
                description=description,
                created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
            s.add(lab)
            return Lab(
                id=lab.id,
                name=lab.name,
                host=lab.host,
                port=int(lab.port),
                description=lab.description,
                created_at=lab.created_at,
            )

    def list(self) -> List[Lab]:
        with session_scope(self.db_path) as s:
            rows = s.execute(select(LabORM)).scalars().all()
            return [
                Lab(
                    id=r.id,
                    name=r.name,
                    host=r.host,
                    port=int(r.port),
                    description=r.description,
                    created_at=r.created_at,
                )
                for r in rows
            ]

    def remove(self, name: str) -> bool:
        with session_scope(self.db_path) as s:
            row = s.execute(select(LabORM).where(LabORM.name == name)).scalar_one_or_none()
            if row is None:
                return False
            s.delete(row)
            return True