"""SSE streaming endpoint tests.

Uses httpx.AsyncClient with ASGI transport to exercise the event_generator in the same event loop.
Mocks time.monotonic() and asyncio.sleep() for fast, deterministic timeout tests.
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
from backend.models import ScanCreate, ScanProgress, ScanStatus


@pytest.fixture
async def async_client():
    """Create an async client with ASGI transport for testing SSE."""
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


async def _create_scan(db, scan_id, status=ScanStatus.RUNNING, progress_logs=None):
    """Helper to create a scan with optional progress logs."""
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

    return scan_id


async def _parse_sse_lines(response):
    """Parse SSE lines from an async streaming response into a list of event dicts."""
    import ast
    events = []
    current_event = None
    current_data = []

    async for line in response.aiter_lines():
        if not line:
            if current_event is not None:
                events.append({
                    "event": current_event,
                    "data": ast.literal_eval("".join(current_data)) if current_data else {}
                })
                current_event = None
                current_data = []
            continue

        if line.startswith("event:"):
            current_event = line[6:].strip()
        elif line.startswith("data:"):
            current_data.append(line[5:].strip())

    # Handle final event if stream ended without blank line
    if current_event is not None:
        events.append({
            "event": current_event,
            "data": ast.literal_eval("".join(current_data)) if current_data else {}
        })

    return events


class TestSSEProgressStream:
    """Tests for /api/scans/{scan_id}/progress SSE endpoint."""

    @pytest.mark.asyncio
    async def test_404_nonexistent_scan(self, async_client, mock_db):
        """Nonexistent scan_id returns 404 before generator starts."""
        scan_id = uuid4()
        response = await async_client.get(f"/api/scans/{scan_id}/progress")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_already_completed_scan_emits_complete_immediately(self, async_client, mock_db):
        """Scan with status=completed emits 'complete' event on first iteration and terminates."""
        scan_id = await _create_scan(mock_db, uuid4(), status=ScanStatus.COMPLETED)

        async with async_client.stream("GET", f"/api/scans/{scan_id}/progress") as response:
            assert response.status_code == 200
            events = await _parse_sse_lines(response)

        # Should have exactly one event: complete
        assert len(events) == 1
        assert events[0]["event"] == "complete"
        assert events[0]["data"]["status"] == "completed"
        assert "error" in events[0]["data"]

    @pytest.mark.asyncio
    async def test_live_progress_with_midstream_completion(self, async_client, mock_db):
        """Running scan emits progress events, then completes when status changes mid-stream."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.RUNNING, progress_logs=[
            {
                "scan_id": str(scan_id),
                "timestamp": datetime.now(UTC).isoformat(),
                "level": "info",
                "message": "Starting scan",
                "stage": "scan",
            },
        ])

        sleep_call_count = 0

        async def controlled_sleep(duration):
            nonlocal sleep_call_count
            sleep_call_count += 1
            if sleep_call_count == 1:
                # After first sleep (i.e., after first iteration yields progress),
                # mark scan as completed so the next iteration exits
                await mock_db.scans.update_one(
                    {"scan_id": str(scan_id)},
                    {"$set": {"status": ScanStatus.COMPLETED.value, "updated_at": datetime.now(UTC)}}
                )

        # Mock time.monotonic in backend.main only to return same value (no timeout)
        # Use a context manager to limit scope
        with (
            patch("backend.main.time.monotonic", return_value=0.0),
            patch("asyncio.sleep", side_effect=controlled_sleep),
        ):
            async with async_client.stream("GET", f"/api/scans/{scan_id}/progress") as response:
                assert response.status_code == 200
                events = await _parse_sse_lines(response)

        # Should have: progress event(s) then complete event
        assert len(events) >= 2
        assert events[0]["event"] == "progress"
        assert events[0]["data"]["message"] == "Starting scan"
        assert events[-1]["event"] == "complete"
        assert events[-1]["data"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_timeout_safeguard_terminates_stream(self, async_client, mock_db):
        """Stream terminates with timeout event when max duration exceeded."""
        scan_id = uuid4()
        await _create_scan(mock_db, scan_id, status=ScanStatus.RUNNING)

        # Override config for fast test
        original_max = settings.SSE_STREAM_MAX_DURATION_SECONDS
        original_poll = settings.SSE_STREAM_POLL_INTERVAL_SECONDS
        settings.SSE_STREAM_MAX_DURATION_SECONDS = 2
        settings.SSE_STREAM_POLL_INTERVAL_SECONDS = 0.5

        # Mock time.monotonic to advance: 0 -> 0.5 -> 1.0 -> 1.5 -> 2.1 (exceeds 2) -> then return large value
        time_values = [0.0, 0.5, 1.0, 1.5, 2.1, 10.0, 20.0]

        def mock_monotonic():
            try:
                return next(time_iter)
            except StopIteration:
                return 100.0  # After exhaustion, return large value to avoid issues

        time_iter = iter(time_values)

        # Use context managers to limit patch scope to the test body only
        with (
            patch("backend.main.time.monotonic", side_effect=mock_monotonic),
            patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            async with async_client.stream("GET", f"/api/scans/{scan_id}/progress") as response:
                assert response.status_code == 200
                events = await _parse_sse_lines(response)

        # Should have timeout event as last event
        assert len(events) >= 1
        assert events[-1]["event"] == "timeout"
        assert "timeout" in events[-1]["data"]["message"].lower()
        assert mock_sleep.call_count >= 2  # called at least twice before timeout

        # Restore config
        settings.SSE_STREAM_MAX_DURATION_SECONDS = original_max
        settings.SSE_STREAM_POLL_INTERVAL_SECONDS = original_poll

    @pytest.mark.asyncio
    async def test_progress_events_have_correct_timestamp_format(self, async_client, mock_db):
        """Progress events have timestamp as string (already ISO format from DB)."""
        scan_id = uuid4()
        ts = datetime.now(UTC).isoformat()
        await _create_scan(mock_db, scan_id, status=ScanStatus.RUNNING, progress_logs=[
            {
                "scan_id": str(scan_id),
                "timestamp": ts,
                "level": "info",
                "message": "Test message",
                "stage": "test",
            },
        ])

        # Override timeout for fast test
        original_max = settings.SSE_STREAM_MAX_DURATION_SECONDS
        settings.SSE_STREAM_MAX_DURATION_SECONDS = 2

        # Use a callable that never exhausts
        time_values = [0.0, 0.5, 2.1]
        call_count = 0

        def mock_monotonic():
            nonlocal call_count
            if call_count < len(time_values):
                val = time_values[call_count]
                call_count += 1
                return val
            return 100.0  # After test values, return large to avoid further issues

        try:
            with (
                patch("backend.main.time.monotonic", side_effect=mock_monotonic),
                patch("asyncio.sleep", new_callable=AsyncMock),
            ):
                async with async_client.stream("GET", f"/api/scans/{scan_id}/progress") as response:
                    assert response.status_code == 200
                    events = await _parse_sse_lines(response)
        finally:
            settings.SSE_STREAM_MAX_DURATION_SECONDS = original_max

        assert len(events) >= 1
        assert events[0]["event"] == "progress"
        assert events[0]["data"]["timestamp"] == ts  # Already a string, passed through
        assert isinstance(events[0]["data"]["timestamp"], str)