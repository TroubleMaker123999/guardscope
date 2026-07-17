"""Unified finding model.

The :class:`Finding` Pydantic model is the canonical normalized representation
of a vulnerability finding that flows through every parser, the database, the
API and the reporting layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from uuid import uuid4

from pydantic import BaseModel, BeforeValidator, Field, field_validator
from typing_extensions import Annotated


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Finding(BaseModel):
    """A normalized vulnerability finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    fingerprint: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    cvss: float = 0.0
    cwe: List[str] = Field(default_factory=list)
    owasp: List[str] = Field(default_factory=list)
    source: str = "unknown"
    asset: str = ""
    evidence: str = ""
    remediation: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    @field_validator("cvss", mode="before")
    @classmethod
    def _coerce_cvss(cls, v):
        if v is None or v == "":
            return 0.0
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.0

    @field_validator("cvss", mode="after")
    @classmethod
    def _clip_cvss(cls, v: float) -> float:
        if v is None:
            return 0.0
        try:
            v = float(v)
        except (TypeError, ValueError):
            return 0.0
        if v < 0.0:
            return 0.0
        if v > 10.0:
            return 10.0
        return round(v, 1)

    @field_validator("cwe", "owasp", mode="before")
    @classmethod
    def _split_strings(cls, v):
        if v is None:
            return []
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        if isinstance(v, (list, tuple)):
            return [str(x).strip() for x in v if str(x).strip()]
        return [str(v)]

    def to_dict(self) -> dict:
        d = self.model_dump()
        d["created_at"] = self.created_at.isoformat()
        d["updated_at"] = self.updated_at.isoformat()
        return d


class EvidenceRecord(BaseModel):
    """Raw evidence supporting a finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    finding_id: str
    source: str = ""
    snippet: str = ""
    created_at: datetime = Field(default_factory=_utcnow)


class AuditRecord(BaseModel):
    """Append-only audit entry."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    event: str
    payload: str = ""
    created_at: datetime = Field(default_factory=_utcnow)