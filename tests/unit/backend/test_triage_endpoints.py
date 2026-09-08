"""E2E tests for all 6 triage endpoints against mongomock.

Uses httpx.AsyncClient with ASGI transport, same pattern as B3 SSE tests.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import pytest
from httpx import ASGITransport

from backend.config import settings
from backend.database import reset_connection_state
from backend.main import app
from backend.models import (
    ScanCreate,
    ScanProgress,
    ScanStatus,
    SeverityLevel,
    TriageMode,
    TriageResult,
    TriageRunCreate,
    TriageSource,
)


@pytest.fixture
async def async_client():
    """Create an async client with ASGI transport for testing endpoints."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture(autouse=True)
async def mock_db():
    """Replace the global DB connection with mongomock for each test."""
    reset_connection_state()
    from mongomock_motor import AsyncMongoMockClient

    import backend.database as database_module

    client = AsyncMongoMockClient()
    db = client["test_db"]

    original_get_db = database_module.get_db

    async def mock_get_db():
        return db

    database_module.get_db = mock_get_db
    database_module._db = db
    database_module._client = client

    yield db

    database_module.get_db = original_get_db
    reset_connection_state()
    client.close()


async def _create_scan(
    db,
    scan_id,
    status=ScanStatus.COMPLETED,
    progress_logs=None,
    findings=None,
):
    """Helper to create a scan with optional progress logs and findings."""
    scan_data = ScanCreate(
        scan_id=scan_id,
        url="https://example.com",
        max_pages=10,
        max_depth=1,
        timeout=10.0,
        allow_write_tests=False,
        status=status,
        progress=ScanProgress(),
        target_url="https://example.com",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await db.scans.insert_one(scan_data.model_dump(mode="json"))

    if progress_logs:
        await db.progress_logs.insert_many(progress_logs)

    if findings:
        await db.findings.insert_many(findings)

    return scan_id


async def _create_finding(scan_id, finding_id="finding-123", **overrides):
    """Create a realistic finding document."""
    base = {
        "id": finding_id,
        "scan_id": str(scan_id),
        "check": "test_check",
        "title": "Test Finding",
        "severity": SeverityLevel.HIGH.value,
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
    base.update(overrides)
    return base


async def _create_triage_run(db, scan_id, mode=TriageMode.BASELINE, results=None, status="completed"):
    """Create a triage run document."""
    triage_data = TriageRunCreate(scan_id=scan_id, mode=mode)
    triage_doc = triage_data.model_dump(mode="json")
    if results:
        triage_doc["results"] = [r.model_dump(mode="json") for r in results]
    if status:
        triage_doc["status"] = status
        if status in ("completed", "failed"):
            triage_doc["completed_at"] = datetime.now(UTC).isoformat()
    await db.triage_runs.insert_one(triage_doc)
    return triage_data


def _create_triage_result(finding_id, revised_priority=3, source=TriageSource.BASELINE, **overrides):
    """Create a TriageResult for testing."""
    base = TriageResult(
        finding_id=finding_id,
        finding_title=f"Finding {finding_id}",
        explanation="Test explanation",
        exploitability=3,
        fix="Test fix",
        revised_priority=revised_priority,
        source=source,
        prompt_version="v1",
        original_severity=SeverityLevel.HIGH,
    )
    # Can't easily override frozen fields, so just return base
    return base


class TestStartTriage:
    """Tests for POST /api/scans/{scan_id}/triage"""

    @pytest.mark.asyncio
    async def test_happy_path_baseline(self, async_client, mock_db):
        """Completed scan → 202, triage doc created, background task fires.

        Note: Background task runs synchronously in test (due to mocked sleep),
        so status becomes 'completed' by the time we check. This is expected.
        """
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.COMPLETED)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            response = await async_client.post(
                f"/api/scans/{scan_id}/triage",
                params={"mode": "baseline"},
            )

        assert response.status_code == 202
        data = response.json()
        assert data["scan_id"] == str(scan_id)
        assert data["mode"] == "baseline"
        assert data["status"] in ("pending", "completed")  # Background task may have completed
        assert "triage_id" in data

        # Verify triage run was inserted
        triage_doc = await mock_db.triage_runs.find_one({"scan_id": str(scan_id)})
        assert triage_doc is not None
        assert triage_doc["mode"] == "baseline"
        assert triage_doc["status"] in ("pending", "completed")

    @pytest.mark.asyncio
    async def test_happy_path_llm(self, async_client, mock_db):
        """Completed scan with mode=llm → 202, triage doc created."""
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.COMPLETED)

        with patch("asyncio.sleep", new_callable=AsyncMock):
            response = await async_client.post(
                f"/api/scans/{scan_id}/triage",
                params={"mode": "llm"},
            )

        assert response.status_code == 202
        data = response.json()
        assert data["mode"] == "llm"

    @pytest.mark.asyncio
    async def test_scan_not_found(self, async_client, mock_db):
        """Nonexistent scan_id → 404."""
        response = await async_client.post(
            f"/api/scans/{uuid4()}/triage",
            params={"mode": "baseline"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_scan_not_completed(self, async_client, mock_db):
        """Scan with status=running → 400."""
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.RUNNING)

        response = await async_client.post(
            f"/api/scans/{scan_id}/triage",
            params={"mode": "baseline"},
        )
        assert response.status_code == 400
        assert "not completed" in response.json()["detail"]


class TestListTriageRuns:
    """Tests for GET /api/scans/{scan_id}/triage"""

    @pytest.mark.asyncio
    async def test_returns_runs_in_descending_order(self, async_client, mock_db):
        """Returns runs ordered by created_at descending."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        # Create 3 runs with different timestamps
        for i in range(3):
            triage_data = TriageRunCreate(scan_id=scan_id, mode=TriageMode.BASELINE)
            triage_doc = triage_data.model_dump(mode="json")
            # Manually set created_at to ensure order
            from datetime import timedelta
            triage_doc["created_at"] = datetime.now(UTC) - timedelta(minutes=i)
            await mock_db.triage_runs.insert_one(triage_doc)

        response = await async_client.get(f"/api/scans/{scan_id}/triage")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 3
        # First should be most recent
        created_times = [datetime.fromisoformat(r["created_at"]) for r in data]
        assert created_times == sorted(created_times, reverse=True)

    @pytest.mark.asyncio
    async def test_empty_for_scan_without_runs(self, async_client, mock_db):
        """Returns empty list for scan with no triage runs."""
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.COMPLETED)

        response = await async_client.get(f"/api/scans/{scan_id}/triage")
        assert response.status_code == 200
        assert response.json() == []


class TestGetTriage:
    """Tests for GET /api/triage/{triage_id}"""

    @pytest.mark.asyncio
    async def test_happy_path(self, async_client, mock_db):
        """Returns triage run with results."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        result = _create_triage_result("finding-1")
        await _create_triage_run(mock_db, scan_id, mode=TriageMode.BASELINE, results=[result])

        # Get the triage_id from the inserted doc
        triage_doc = await mock_db.triage_runs.find_one({"scan_id": str(scan_id)})
        triage_id = triage_doc["triage_id"]

        response = await async_client.get(f"/api/triage/{triage_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["triage_id"] == triage_id
        assert data["scan_id"] == str(scan_id)
        assert len(data["results"]) == 1
        assert data["results"][0]["finding_id"] == "finding-1"

    @pytest.mark.asyncio
    async def test_not_found(self, async_client, mock_db):
        """Nonexistent triage_id → 404."""
        response = await async_client.get(f"/api/triage/{uuid4()}")
        assert response.status_code == 404


class TestCompareTriage:
    """Tests for GET /api/scans/{scan_id}/triage/compare"""

    @pytest.mark.asyncio
    async def test_both_modes_present_with_changed_priorities(self, async_client, mock_db):
        """Both baseline and LLM runs exist; changed_priority correctly computed."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        # Baseline: finding-1 priority=2, finding-2 priority=3
        baseline_results = [
            _create_triage_result("finding-1", revised_priority=2, source=TriageSource.BASELINE),
            _create_triage_result("finding-2", revised_priority=3, source=TriageSource.BASELINE),
        ]
        # LLM: finding-1 priority=1 (changed!), finding-2 priority=3 (same), finding-3 priority=4 (LLM-only)
        llm_results = [
            _create_triage_result("finding-1", revised_priority=1, source=TriageSource.LLM),
            _create_triage_result("finding-2", revised_priority=3, source=TriageSource.LLM),
            _create_triage_result("finding-3", revised_priority=4, source=TriageSource.LLM),
        ]

        await _create_triage_run(mock_db, scan_id, mode=TriageMode.BASELINE, results=baseline_results)
        await _create_triage_run(mock_db, scan_id, mode=TriageMode.LLM, results=llm_results)

        response = await async_client.get(f"/api/scans/{scan_id}/triage/compare")
        assert response.status_code == 200
        data = response.json()

        assert len(data["baseline"]) == 2
        assert len(data["llm"]) == 3
        assert data["baseline_only"] == []  # both baseline findings in LLM
        assert data["llm_only"] == ["finding-3"]
        assert len(data["changed_priority"]) == 1
        assert data["changed_priority"][0] == {
            "finding_id": "finding-1",
            "baseline_priority": 2,
            "llm_priority": 1,
        }

    @pytest.mark.asyncio
    async def test_only_baseline_present(self, async_client, mock_db):
        """Only baseline run exists → llm empty, baseline_only populated."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        baseline_results = [_create_triage_result("finding-1", revised_priority=2)]
        await _create_triage_run(mock_db, scan_id, mode=TriageMode.BASELINE, results=baseline_results)

        response = await async_client.get(f"/api/scans/{scan_id}/triage/compare")
        assert response.status_code == 200
        data = response.json()

        assert len(data["baseline"]) == 1
        assert data["llm"] == []
        assert data["baseline_only"] == ["finding-1"]
        assert data["llm_only"] == []
        assert data["changed_priority"] == []

    @pytest.mark.asyncio
    async def test_only_llm_present(self, async_client, mock_db):
        """Only LLM run exists → baseline empty, llm_only populated."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        llm_results = [_create_triage_result("finding-1", revised_priority=1, source=TriageSource.LLM)]
        await _create_triage_run(mock_db, scan_id, mode=TriageMode.LLM, results=llm_results)

        response = await async_client.get(f"/api/scans/{scan_id}/triage/compare")
        assert response.status_code == 200
        data = response.json()

        assert data["baseline"] == []
        assert len(data["llm"]) == 1
        assert data["baseline_only"] == []
        assert data["llm_only"] == ["finding-1"]
        assert data["changed_priority"] == []

    @pytest.mark.asyncio
    async def test_neither_present(self, async_client, mock_db):
        """No triage runs → all empty lists."""
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.COMPLETED)

        response = await async_client.get(f"/api/scans/{scan_id}/triage/compare")
        assert response.status_code == 200
        data = response.json()

        assert data["baseline"] == []
        assert data["llm"] == []
        assert data["baseline_only"] == []
        assert data["llm_only"] == []
        assert data["changed_priority"] == []


class TestRegenerateTriage:
    """Tests for POST /api/triage/{triage_id}/regenerate"""

    @pytest.mark.asyncio
    async def test_returns_501_with_workaround_message(self, async_client, mock_db):
        """Returns 501 with clear message pointing to full re-triage."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)
        await _create_triage_run(mock_db, scan_id, mode=TriageMode.LLM)

        triage_doc = await mock_db.triage_runs.find_one({"scan_id": str(scan_id)})
        triage_id = triage_doc["triage_id"]

        # Need a finding to exist for the 501 path (it validates finding exists)
        finding = await _create_finding(scan_id, "finding-1")
        await mock_db.findings.insert_one(finding)

        response = await async_client.post(
            f"/api/triage/{triage_id}/regenerate",
            params={"finding_id": "finding-1"},
        )
        assert response.status_code == 501
        detail = response.json()["detail"]
        assert "Single-finding regeneration not yet implemented" in detail
        assert "mode=llm" in detail
        assert str(scan_id) in detail

    @pytest.mark.asyncio
    async def test_triage_not_found(self, async_client, mock_db):
        """Nonexistent triage_id → 404."""
        response = await async_client.post(
            f"/api/triage/{uuid4()}/regenerate",
            params={"finding_id": "finding-1"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_baseline_mode_rejected(self, async_client, mock_db):
        """Baseline triage run → 400."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)
        await _create_triage_run(mock_db, scan_id, mode=TriageMode.BASELINE)

        triage_doc = await mock_db.triage_runs.find_one({"scan_id": str(scan_id)})
        triage_id = triage_doc["triage_id"]

        response = await async_client.post(
            f"/api/triage/{triage_id}/regenerate",
            params={"finding_id": "finding-1"},
        )
        assert response.status_code == 400
        assert "Can only regenerate LLM triage runs" in response.json()["detail"]


class TestKBContext:
    """Tests for GET /api/triage/kb-context"""

    @pytest.mark.asyncio
    async def test_happy_path_real_retriever(self, async_client, mock_db):
        """Real retriever call against KB files returns relevant context."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        # Insert a finding that matches a KB topic (e.g., "cors")
        finding = await _create_finding(
            scan_id,
            "finding-cors",
            check="cors",
            title="CORS Misconfiguration",
            severity=SeverityLevel.MEDIUM.value,
        )
        await mock_db.findings.insert_one(finding)

        # Override timeout for fast test
        original_max = settings.SSE_STREAM_MAX_DURATION_SECONDS
        settings.SSE_STREAM_MAX_DURATION_SECONDS = 2

        try:
            with (
                patch("backend.main.time.monotonic", return_value=0.0),
                patch("asyncio.sleep", new_callable=AsyncMock),
            ):
                response = await async_client.get(
                    "/api/triage/kb-context",
                    params={"finding_id": "finding-cors", "scan_id": str(scan_id)},
                )
        finally:
            settings.SSE_STREAM_MAX_DURATION_SECONDS = original_max

        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "finding-cors"
        assert "context" in data
        # Should return at least one context snippet (KB has cors.md)
        assert len(data["context"]) >= 1
        # Topic should be relevant to CORS
        topics = [c["topic"] for c in data["context"]]
        assert any("cors" in t.lower() for t in topics)

    @pytest.mark.asyncio
    async def test_finding_not_found(self, async_client, mock_db):
        """Nonexistent finding_id → 404."""
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.COMPLETED)

        response = await async_client.get(
            "/api/triage/kb-context",
            params={"finding_id": "nonexistent", "scan_id": str(scan_id)},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_missing_wstg_id_degrades_to_unknown(self, async_client, mock_db):
        """Stale doc missing wstg_id → degrades to 'UNKNOWN' and still returns context."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.COMPLETED)

        # Insert finding WITHOUT wstg_id (legacy document)
        finding = await _create_finding(
            scan_id,
            "finding-legacy",
            check="security_headers",
            title="Missing Security Headers",
        )
        finding.pop("wstg_id")  # Remove wstg_id entirely
        await mock_db.findings.insert_one(finding)

        original_max = settings.SSE_STREAM_MAX_DURATION_SECONDS
        settings.SSE_STREAM_MAX_DURATION_SECONDS = 2

        try:
            with (
                patch("backend.main.time.monotonic", return_value=0.0),
                patch("asyncio.sleep", new_callable=AsyncMock),
            ):
                response = await async_client.get(
                    "/api/triage/kb-context",
                    params={"finding_id": "finding-legacy", "scan_id": str(scan_id)},
                )
        finally:
            settings.SSE_STREAM_MAX_DURATION_SECONDS = original_max

        assert response.status_code == 200
        data = response.json()
        assert data["finding_id"] == "finding-legacy"
        assert len(data["context"]) >= 1  # Still returns context despite missing wstg_id