import uuid
from dataclasses import dataclass, field
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Evidence:
    url: str
    snippet: str
    matched_pattern: str | None = None
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    response_status: int | None = None


@dataclass
class Finding:
    check: str
    title: str
    severity: SeverityLevel
    score: int
    impact: int
    likelihood: int
    wstg_id: str
    attck_ids: list[str]
    evidence: Evidence
    confidence: float
    remediation: str
    references: list[str]
    id: str = field(default_factory=lambda: f"finding-{uuid.uuid4().hex[:8]}")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "check": self.check,
            "title": self.title,
            "severity": self.severity.value,
            "score": self.score,
            "impact": self.impact,
            "likelihood": self.likelihood,
            "wstg_id": self.wstg_id,
            "attck_ids": self.attck_ids,
            "evidence": {
                "url": self.evidence.url,
                "snippet": self.evidence.snippet,
                "matched_pattern": self.evidence.matched_pattern,
                "request_headers": self.evidence.request_headers,
                "response_headers": self.evidence.response_headers,
                "response_status": self.evidence.response_status,
            },
            "confidence": self.confidence,
            "remediation": self.remediation,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        evidence_data = data.get("evidence", {})
        evidence = Evidence(
            url=evidence_data.get("url", ""),
            snippet=evidence_data.get("snippet", ""),
            matched_pattern=evidence_data.get("matched_pattern"),
            request_headers=evidence_data.get("request_headers", {}),
            response_headers=evidence_data.get("response_headers", {}),
            response_status=evidence_data.get("response_status"),
        )
        return cls(
            id=data.get("id", f"finding-{uuid.uuid4().hex[:8]}"),
            check=data["check"],
            title=data["title"],
            severity=SeverityLevel(data["severity"]),
            score=data["score"],
            impact=data["impact"],
            likelihood=data["likelihood"],
            wstg_id=data["wstg_id"],
            attck_ids=data["attck_ids"],
            evidence=evidence,
            confidence=data["confidence"],
            remediation=data["remediation"],
            references=data["references"],
        )