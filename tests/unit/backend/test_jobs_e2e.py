"""End-to-end tests for background job functions against mongomock.

These tests exercise the actual MongoDB insert/update paths with real
UUID, Enum, and datetime values to catch BSON serialization bugs
that type checkers and unit tests miss.
"""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from mongomock_motor import AsyncMongoMockClient

from backend.database import reset_connection_state
from backend.jobs import log_progress, run_baseline_triage, update_scan_status
from backend.models import (
    ScanCreate,
    ScanProgress,
    ScanStatus,
    SeverityLevel,
    TriageMode,
    TriageRunCreate,
)


@pytest.fixture(autouse=True)
async def mock_db():
    """Replace the global DB connection with mongomock for each test."""
    reset_connection_state()
    client = AsyncMongoMockClient()
    db = client["test_db"]

    # Monkey-patch get_db to return our mock
    import backend.database as database_module
    original_get_db = database_module.get_db

    async def mock_get_db():
        return db

    database_module.get_db = mock_get_db
    database_module._db = db
    database_module._client = client

    yield db

    # Restore
    database_module.get_db = original_get_db
    reset_connection_state()
    client.close()


@pytest.mark.asyncio
async def test_log_progress_inserts_uuid_enum_datetime(mock_db):
    """log_progress() must serialize UUID, Enum, and datetime to BSON-safe JSON.

    This is the exact failure mode: ProgressLog contains a UUID field,
    and without mode="json", pymongo fails to encode the native uuid.UUID.
    """
    scan_id = uuid4()

    # This should not raise - the bug was BSON encoding failure on UUID
    await log_progress(scan_id, "info", "Test message", "test_stage")

    # Verify the document was inserted with correct serialized types
    doc = await mock_db.progress_logs.find_one({"scan_id": str(scan_id)})
    assert doc is not None
    assert doc["scan_id"] == str(scan_id)  # UUID serialized to string
    assert doc["level"] == "info"
    assert doc["message"] == "Test message"
    assert doc["stage"] == "test_stage"
    # timestamp should be ISO string (datetime serialized)
    assert isinstance(doc["timestamp"], str)


@pytest.mark.asyncio
async def test_run_baseline_triage_e2e_with_real_finding_data(mock_db):
    """Full smoke test: run_baseline_triage() with realistic finding data.

    The finding data includes:
    - UUID (scan_id, finding id)
    - SeverityLevel enum
    - datetime (created_at)
    - All other required fields for a valid Finding

    This exercises the complete path: load findings -> triage -> store results.
    """
    scan_id = uuid4()

    # Create a scan document (prerequisite for triage)
    scan_data = ScanCreate(
        scan_id=scan_id,
        url="https://example.com",
        max_pages=10,
        max_depth=1,
        timeout=10.0,
        allow_write_tests=False,
        status=ScanStatus.COMPLETED,
        progress=ScanProgress(),
        target_url="https://example.com",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await mock_db.scans.insert_one(scan_data.model_dump(mode="json"))

    # Insert a realistic finding with all the types that need JSON serialization
    finding_id = "finding-123"
    finding_doc = {
        "id": finding_id,
        "scan_id": str(scan_id),
        "check": "test_check",
        "title": "Test Finding",
        "severity": SeverityLevel.HIGH.value,  # Enum value
        "score": 75,
        "impact": 4,
        "likelihood": 4,
        "wstg_id": "WSTG-01",
        "attck_ids": ["T1234"],
        "evidence": {
            "url": "https://example.com/test",
            "snippet": "test evidence",
            "matched_pattern": "pattern",
            "request_headers": {},
            "response_headers": {},
            "response_status": 200,
        },
        "confidence": 0.9,
        "remediation": "Fix it",
        "references": ["https://example.com/ref"],
    }
    await mock_db.findings.insert_one(finding_doc)

    # Create triage run and INSERT it first (like the API endpoint does)
    triage_data = TriageRunCreate(
        scan_id=scan_id,
        mode=TriageMode.BASELINE,
    )
    await mock_db.triage_runs.insert_one(triage_data.model_dump(mode="json"))

    # This should not raise - the bug was BSON encoding failure on UUID/Enum/datetime
    await run_baseline_triage(scan_id, triage_data)

    # Verify triage run was updated with results
    triage_doc = await mock_db.triage_runs.find_one({"triage_id": str(triage_data.triage_id)})
    assert triage_doc is not None
    assert triage_doc["scan_id"] == str(scan_id)
    assert triage_doc["mode"] == "baseline"
    assert triage_doc["status"] == "completed"
    assert triage_doc["completed_at"] is not None
    assert isinstance(triage_doc["results"], list)
    assert len(triage_doc["results"]) == 1

    # Verify result has correct serialized types
    result = triage_doc["results"][0]
    assert result["finding_id"] == finding_id
    assert result["source"] == "baseline"
    assert isinstance(result["exploitability"], int)
    assert isinstance(result["revised_priority"], int)
    assert result["original_severity"] == SeverityLevel.HIGH.value


@pytest.mark.asyncio
async def test_update_scan_status_serializes_progress(mock_db):
    """update_scan_status() must serialize ScanProgress (which may contain nested types)."""
    scan_id = uuid4()

    # Create a scan first
    scan_data = ScanCreate(
        scan_id=scan_id,
        url="https://example.com",
        max_pages=10,
        max_depth=1,
        timeout=10.0,
        allow_write_tests=False,
        status=ScanStatus.PENDING,
        progress=ScanProgress(),
        target_url="https://example.com",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await mock_db.scans.insert_one(scan_data.model_dump(mode="json"))

    # Update with progress containing findings_found (int) and current_url (str)
    progress = ScanProgress(
        pages_crawled=5,
        current_check="test_check",
        current_url="https://example.com/page",
        findings_found=3,
        errors=0,
    )

    await update_scan_status(scan_id, ScanStatus.RUNNING, progress=progress)

    doc = await mock_db.scans.find_one({"scan_id": str(scan_id)})
    assert doc is not None
    assert doc["status"] == "running"
    assert doc["progress"]["pages_crawled"] == 5
    assert doc["progress"]["current_url"] == "https://example.com/page"
    assert doc["progress"]["findings_found"] == 3
