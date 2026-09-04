from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from backend.models import (
    Evidence,
    Finding,
    FindingResponse,
    ProgressLog,
    ScanCreate,
    ScanProgress,
    ScanStatus,
    SeverityLevel,
    TriageMode,
    TriageResult,
    TriageRunCreate,
    TriageRunResponse,
    TriageSource,
)


def _serialize_for_mongo(obj):
    """Convert Pydantic model dict to MongoDB-compatible format."""
    if isinstance(obj, dict):
        return {k: _serialize_for_mongo(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_for_mongo(v) for v in obj]
    elif isinstance(obj, UUID) or hasattr(obj, '__str__') and type(obj).__name__ == 'HttpUrl':
        return str(obj)
    elif isinstance(obj, datetime):
        return obj
    else:
        return obj


@pytest.mark.asyncio
async def test_scan_create_roundtrip(mongomock_db):
    scan = ScanCreate(
        scan_id=uuid4(),
        url="https://example.com",
        target_url="https://example.com",
        max_pages=20,
        max_depth=2,
        timeout=10.0,
        allow_write_tests=False,
        status=ScanStatus.PENDING,
        progress=ScanProgress(pages_crawled=5, findings_found=3),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        error=None,
    )
    doc = _serialize_for_mongo(scan.model_dump())
    result = await mongomock_db.scans.insert_one(doc)
    fetched = await mongomock_db.scans.find_one({"_id": result.inserted_id})
    assert fetched is not None
    assert UUID(fetched["scan_id"]) == scan.scan_id
    assert fetched["target_url"] == scan.target_url
    assert fetched["max_pages"] == scan.max_pages
    assert fetched["max_depth"] == scan.max_depth
    assert fetched["timeout"] == scan.timeout
    assert fetched["allow_write_tests"] == scan.allow_write_tests
    assert fetched["status"] == scan.status.value
    assert fetched["progress"]["pages_crawled"] == scan.progress.pages_crawled
    assert fetched["progress"]["findings_found"] == scan.progress.findings_found
    assert fetched["error"] is None


@pytest.mark.asyncio
async def test_finding_roundtrip(mongomock_db):
    evidence = Evidence(
        url="https://example.com/main.js",
        snippet="const API_KEY = 'secret'",
        matched_pattern="API_KEY",
        request_headers={},
        response_headers={"content-type": "application/javascript"},
        response_status=200,
    )
    finding = Finding(
        id="finding-123",
        check="exposed_secrets",
        title="Exposed API Key",
        severity=SeverityLevel.CRITICAL,
        score=20,
        impact=5,
        likelihood=4,
        wstg_id="WSTG-AUTH-07",
        attck_ids=["T1552"],
        evidence=evidence,
        confidence=0.95,
        remediation="Move to server-side env var",
        references=["https://example.com/security"],
    )
    finding_resp = FindingResponse(
        scan_id=uuid4(),
        created_at=datetime.now(UTC),
        **finding.model_dump()
    )
    doc = _serialize_for_mongo(finding_resp.model_dump())
    result = await mongomock_db.findings.insert_one(doc)
    fetched = await mongomock_db.findings.find_one({"_id": result.inserted_id})
    assert fetched is not None
    assert fetched["id"] == finding.id
    assert fetched["check"] == finding.check
    assert fetched["title"] == finding.title
    assert fetched["severity"] == finding.severity.value
    assert fetched["score"] == finding.score
    assert fetched["impact"] == finding.impact
    assert fetched["likelihood"] == finding.likelihood
    assert fetched["wstg_id"] == finding.wstg_id
    assert fetched["attck_ids"] == finding.attck_ids
    assert fetched["evidence"]["url"] == evidence.url
    assert fetched["evidence"]["snippet"] == evidence.snippet
    assert fetched["evidence"]["matched_pattern"] == evidence.matched_pattern
    assert fetched["confidence"] == finding.confidence
    assert fetched["remediation"] == finding.remediation
    assert fetched["references"] == finding.references
    assert UUID(fetched["scan_id"]) == finding_resp.scan_id


@pytest.mark.asyncio
async def test_triage_run_roundtrip(mongomock_db):
    triage_result = TriageResult(
        finding_id="finding-123",
        finding_title="Exposed API Key",
        explanation="API key exposed in client-side JS",
        exploitability=5,
        fix="Move to server-side env var",
        revised_priority=5,
        source=TriageSource.LLM,
        prompt_version="v1",
        original_severity=SeverityLevel.CRITICAL,
    )
    triage_run = TriageRunCreate(
        triage_id=uuid4(),
        scan_id=uuid4(),
        mode=TriageMode.LLM,
        status="completed",
        results=[triage_result],
        created_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        error=None,
    )
    triage_resp = TriageRunResponse(**triage_run.model_dump())
    doc = _serialize_for_mongo(triage_resp.model_dump())
    result = await mongomock_db.triage_runs.insert_one(doc)
    fetched = await mongomock_db.triage_runs.find_one({"_id": result.inserted_id})
    assert fetched is not None
    assert UUID(fetched["triage_id"]) == triage_resp.triage_id
    assert UUID(fetched["scan_id"]) == triage_run.scan_id
    assert fetched["mode"] == triage_run.mode.value
    assert fetched["status"] == triage_run.status
    assert len(fetched["results"]) == 1
    assert fetched["results"][0]["finding_id"] == triage_result.finding_id
    assert fetched["results"][0]["explanation"] == triage_result.explanation
    assert fetched["results"][0]["exploitability"] == triage_result.exploitability
    assert fetched["results"][0]["revised_priority"] == triage_result.revised_priority
    assert fetched["results"][0]["source"] == triage_result.source.value
    assert fetched["created_at"] is not None


@pytest.mark.asyncio
async def test_progress_log_roundtrip(mongomock_db):
    progress_log = ProgressLog(
        scan_id=uuid4(),
        timestamp=datetime.now(UTC),
        level="info",
        message="Started crawling",
        stage="crawl",
    )
    doc = _serialize_for_mongo(progress_log.model_dump())
    result = await mongomock_db.progress_logs.insert_one(doc)
    fetched = await mongomock_db.progress_logs.find_one({"_id": result.inserted_id})
    assert fetched is not None
    assert UUID(fetched["scan_id"]) == progress_log.scan_id
    assert fetched["level"] == progress_log.level
    assert fetched["message"] == progress_log.message
    assert fetched["stage"] == progress_log.stage


@pytest.mark.asyncio
async def test_uuid_stored_as_string(mongomock_db):
    scan_id = uuid4()
    scan = ScanCreate(
        scan_id=scan_id,
        url="https://example.com",
        target_url="https://example.com",
        max_pages=20,
        max_depth=2,
        timeout=10.0,
        allow_write_tests=False,
        status=ScanStatus.PENDING,
        progress=ScanProgress(),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    doc = _serialize_for_mongo(scan.model_dump())
    await mongomock_db.scans.insert_one(doc)
    fetched = await mongomock_db.scans.find_one({"scan_id": str(scan_id)})
    assert fetched is not None
    assert isinstance(fetched["scan_id"], str)
    assert UUID(fetched["scan_id"]) == scan_id


@pytest.mark.asyncio
async def test_datetime_utc_naive_preserved(mongomock_db):
    now = datetime.now(UTC).replace(tzinfo=None)
    scan = ScanCreate(
        scan_id=uuid4(),
        url="https://example.com",
        target_url="https://example.com",
        max_pages=20,
        max_depth=2,
        timeout=10.0,
        allow_write_tests=False,
        status=ScanStatus.PENDING,
        progress=ScanProgress(),
        created_at=now,
        updated_at=now,
    )
    doc = _serialize_for_mongo(scan.model_dump())
    await mongomock_db.scans.insert_one(doc)
    fetched = await mongomock_db.scans.find_one({})
    assert fetched is not None
    # MongoDB stores datetime with millisecond precision, so compare with tolerance
    assert abs((fetched["created_at"] - now).total_seconds()) < 0.01
    assert abs((fetched["updated_at"] - now).total_seconds()) < 0.01
    assert fetched["created_at"].tzinfo is None
    assert fetched["updated_at"].tzinfo is None