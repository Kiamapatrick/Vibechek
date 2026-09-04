from datetime import UTC, datetime
from enum import Enum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class TriageMode(str, Enum):
    BASELINE = "baseline"
    LLM = "llm"


class TriageSource(str, Enum):
    BASELINE = "baseline"
    LLM = "llm"


class ScanRequest(BaseModel):
    url: HttpUrl
    max_pages: int = Field(default=20, ge=1, le=1000)
    max_depth: int = Field(default=2, ge=0, le=10)
    timeout: float = Field(default=10.0, ge=1.0, le=300.0)
    allow_write_tests: bool = False


class ScanProgress(BaseModel):
    pages_crawled: int = 0
    current_check: str | None = None
    current_url: str | None = None
    findings_found: int = 0
    errors: int = 0


class ScanResponse(BaseModel):
    scan_id: UUID
    status: ScanStatus
    progress: ScanProgress
    created_at: datetime
    updated_at: datetime
    target_url: str
    error: str | None = None


class ScanCreate(ScanRequest):
    scan_id: UUID = Field(default_factory=uuid4)
    status: ScanStatus = ScanStatus.PENDING
    progress: ScanProgress = Field(default_factory=ScanProgress)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_url: str  # Store as string for MongoDB
    error: str | None = None

    model_config = ConfigDict(
        populate_by_name=True,
    )


class Evidence(BaseModel):
    url: str
    snippet: str
    matched_pattern: str | None = None
    request_headers: dict = {}
    response_headers: dict = {}
    response_status: int | None = None


class Finding(BaseModel):
    id: str
    check: str
    title: str
    severity: SeverityLevel
    score: int
    impact: int
    likelihood: int
    wstg_id: str | None = None
    attck_ids: list[str] = []
    evidence: Evidence
    confidence: float
    remediation: str
    references: list[str] = []


class FindingResponse(Finding):
    scan_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TriageResult(BaseModel):
    finding_id: str
    finding_title: str
    explanation: str
    exploitability: int = Field(ge=1, le=5)
    fix: str
    revised_priority: int = Field(ge=1, le=5)
    source: TriageSource
    prompt_version: str = "v1"
    original_severity: SeverityLevel


class TriageRunCreate(BaseModel):
    scan_id: UUID
    mode: TriageMode
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    results: list[TriageResult] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str | None = None


class TriageRunResponse(TriageRunCreate):
    triage_id: UUID = Field(default_factory=uuid4)


class TriageCompareResponse(BaseModel):
    scan_id: UUID
    baseline: list[TriageResult]
    llm: list[TriageResult]
    baseline_only: list[str]  # finding_ids only in baseline
    llm_only: list[str]       # finding_ids only in LLM
    changed_priority: list[dict]  # {finding_id, baseline_priority, llm_priority}


class ReportFormat(str, Enum):
    PLAIN = "plain"
    JSON = "json"
    BOTH = "both"


class ProgressLog(BaseModel):
    scan_id: UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    level: str  # info, warning, error
    message: str
    stage: str | None = None  # crawl, check, triage, etc.