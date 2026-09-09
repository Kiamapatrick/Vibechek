"""E2E tests for /api/scans/{scan_id}/report endpoint against mongomock.

Uses httpx.AsyncClient with ASGI transport, same pattern as other endpoint test files.
"""

from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest
from httpx import ASGITransport

from backend.database import reset_connection_state
from backend.main import app
from backend.models import ScanCreate, ScanProgress, ScanStatus


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
    plain_report=None,
    json_report=None,
    progress_logs=None,
    findings=None,
):
    """Helper to create a scan with optional report fields, progress logs and findings."""
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
    scan_doc = scan_data.model_dump(mode="json")
    if plain_report is not None:
        scan_doc["plain_report"] = plain_report
    if json_report is not None:
        scan_doc["json_report"] = json_report
    await db.scans.insert_one(scan_doc)

    if progress_logs:
        await db.progress_logs.insert_many(progress_logs)

    if findings:
        await db.findings.insert_many(findings)

    return scan_id


class TestGetReport:
    """Tests for GET /api/scans/{scan_id}/report"""

    @pytest.mark.asyncio
    async def test_not_found(self, async_client, mock_db):
        """Nonexistent scan_id → 404."""
        resp = await async_client.get(f"/api/scans/{uuid4()}/report")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_completed_scan_format_plain_default(self, async_client, mock_db):
        """Completed scan with plain_report, format=plain (default) → 200, text matches."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            plain_report="some real text",
            json_report={"findings": [], "summary": {}},
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report")
        assert resp.status_code == 200
        assert resp.text == "some real text"
        assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    @pytest.mark.asyncio
    async def test_completed_scan_format_plain_explicit(self, async_client, mock_db):
        """Completed scan with plain_report, format=plain (explicit) → 200, text matches."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            plain_report="explicit plain report",
            json_report={"findings": [], "summary": {}},
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=plain")
        assert resp.status_code == 200
        assert resp.text == "explicit plain report"
        assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    @pytest.mark.asyncio
    async def test_completed_scan_format_json(self, async_client, mock_db):
        """Completed scan with json_report, format=json → 200, JSON matches."""
        json_report = {"findings": [{"id": "f1", "title": "Test"}], "summary": {"total": 1}}
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            plain_report="plain text",
            json_report=json_report,
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=json")
        assert resp.status_code == 200
        assert resp.json() == json_report

    @pytest.mark.asyncio
    async def test_completed_scan_format_both(self, async_client, mock_db):
        """Completed scan with both reports, format=both → 200, returns both."""
        plain_report = "plain text report"
        json_report = {"findings": [{"id": "f1"}], "summary": {"total": 1}}
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            plain_report=plain_report,
            json_report=json_report,
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=both")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"plain": plain_report, "json": json_report}

    @pytest.mark.asyncio
    async def test_running_scan_no_report_fields(self, async_client, mock_db):
        """Running scan (no plain_report/json_report keys) → 200, fallback text."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.RUNNING,
            # Deliberately omit plain_report and json_report
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report")
        assert resp.status_code == 200
        assert resp.text == "Report not available"
        assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    @pytest.mark.asyncio
    async def test_completed_scan_empty_json_report(self, async_client, mock_db):
        """Completed scan with plain_report but empty json_report → format=json returns {}."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            plain_report="plain only",
            json_report={},
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=json")
        assert resp.status_code == 200
        assert resp.json() == {}

    @pytest.mark.asyncio
    async def test_completed_scan_missing_json_report_key(self, async_client, mock_db):
        """Completed scan with plain_report but no json_report key → format=json returns {}."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            plain_report="plain only",
            # json_report key omitted entirely
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=json")
        assert resp.status_code == 200
        assert resp.json() == {}

    @pytest.mark.asyncio
    async def test_completed_scan_missing_plain_report_key(self, async_client, mock_db):
        """Completed scan with json_report but no plain_report key → format=plain returns fallback."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.COMPLETED,
            json_report={"findings": []},
            # plain_report key omitted entirely
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=plain")
        assert resp.status_code == 200
        assert resp.text == "Report not available"

    @pytest.mark.asyncio
    async def test_failed_scan_with_reports(self, async_client, mock_db):
        """Failed scan that still has reports → returns reports normally."""
        scan_id = await _create_scan(
            mock_db,
            uuid4(),
            status=ScanStatus.FAILED,
            plain_report="failed but has report",
            json_report={"findings": []},
        )

        resp = await async_client.get(f"/api/scans/{scan_id}/report?format=plain")
        assert resp.status_code == 200
        assert resp.text == "failed but has report"