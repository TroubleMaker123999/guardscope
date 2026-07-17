"""Core domain primitives: Pydantic schemas, fingerprinting, normalization,
deduplication and scoring."""

from .models import (
    Severity,
    Confidence,
    Finding,
    EvidenceRecord,
    AuditRecord,
)
from .fingerprint import fingerprint_finding, fingerprint_from_parts
from .normalize import (
    SEVERITY_RANK,
    severity_to_cvss,
    normalize_severity,
    normalize_confidence,
    map_cwe,
    map_owasp,
)
from .dedupe import deduplicate
from .scoring import risk_score, risk_sort

__all__ = [
    "Severity",
    "Confidence",
    "Finding",
    "EvidenceRecord",
    "AuditRecord",
    "fingerprint_finding",
    "fingerprint_from_parts",
    "SEVERITY_RANK",
    "severity_to_cvss",
    "normalize_severity",
    "normalize_confidence",
    "map_cwe",
    "map_owasp",
    "deduplicate",
    "risk_score",
    "risk_sort",
]