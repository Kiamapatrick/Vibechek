import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient
from pymongo.errors import ServerSelectionTimeoutError

from backend.config import settings
from backend.database import close_mongo_connection, connect_to_mongo, get_db
from backend.exceptions import DatabaseUnavailableError
from backend.main import app


@pytest.mark.asyncio
async def test_get_db_lazy_connects(mock_motor_client, mongomock_db):
    await close_mongo_connection()
    db = await connect_to_mongo()
    assert db is mongomock_db
    mock_motor_client.admin.command.assert_awaited_with("ping")
    db2 = await get_db()
    assert db2 is db


@pytest.mark.asyncio
async def test_get_db_returns_503_on_unreachable():
    await close_mongo_connection()
    import backend.database
    original_client = backend.database.AsyncIOMotorClient
    
    def failing_client(*args, **kwargs):
        raise ServerSelectionTimeoutError("timeout")
    
    backend.database.AsyncIOMotorClient = failing_client
    try:
        with pytest.raises(DatabaseUnavailableError):
            await connect_to_mongo()
    finally:
        backend.database.AsyncIOMotorClient = original_client


@pytest.mark.asyncio
async def test_lazy_connect_on_first_request_returns_503():
    """End-to-end test: app starts without DB, first request gets 503."""
    await close_mongo_connection()
    import backend.database
    original_client = backend.database.AsyncIOMotorClient
    
    def failing_client(*args, **kwargs):
        raise ServerSelectionTimeoutError("timeout")
    
    backend.database.AsyncIOMotorClient = failing_client
    try:
        with TestClient(app) as client:
            response = client.get("/api/scans")
            assert response.status_code == 503
            assert response.json() == {"detail": "Database temporarily unavailable"}
    finally:
        backend.database.AsyncIOMotorClient = original_client


@pytest.mark.asyncio
async def test_concurrent_requests_dont_pile_on_during_outage():
    """10 concurrent get_db() calls during outage -> only 1 connection sequence (not 10)."""
    import backend.database
    backend.database.reset_connection_state()
    original_client = backend.database.AsyncIOMotorClient
    
    class FailingAdmin:
        async def command(self, *args, **kwargs):
            await asyncio.sleep(0.1)  # realistic delay forces genuine interleaving
            raise ServerSelectionTimeoutError("simulated outage")
    
    class FailingClient:
        def __init__(self, *args, **kwargs):
            pass
        
        @property
        def admin(self):
            return FailingAdmin()
        
        def __getitem__(self, key):
            return self
        
        def close(self):
            pass
    
    backend.database.AsyncIOMotorClient = FailingClient
    try:
        # Fire 10 concurrent get_db() calls
        results = await asyncio.gather(
            *[get_db() for _ in range(10)],
            return_exceptions=True
        )
        
        # All should raise DatabaseUnavailableError
        for result in results:
            assert isinstance(result, DatabaseUnavailableError)
        
        # Only ONE connection sequence should have been attempted
        assert backend.database._connect_sequence_count == 1, f"Expected 1 sequence, got {backend.database._connect_sequence_count}"
    finally:
        backend.database.AsyncIOMotorClient = original_client
        backend.database.reset_connection_state()


@pytest.mark.asyncio
async def test_close_mongo_connection_resets_state(mock_motor_client, mongomock_db):
    await close_mongo_connection()
    await connect_to_mongo()
    await close_mongo_connection()
    assert mock_motor_client.close.called
    db2 = await connect_to_mongo()
    assert db2 is mongomock_db


@pytest.mark.asyncio
async def test_indexes_created_on_connect(mock_motor_client, mongomock_db):
    await close_mongo_connection()
    await connect_to_mongo()
    for collection_name in ["scans", "findings", "triage_runs", "progress_logs"]:
        indexes = await mongomock_db[collection_name].list_indexes().to_list(length=None)
        assert len(indexes) >= 2


@pytest.mark.asyncio
async def test_connection_pool_config():
    await close_mongo_connection()
    import backend.database
    original_client = backend.database.AsyncIOMotorClient
    created_config = {}
    
    def capture_client(*args, **kwargs):
        created_config.update(kwargs)
        mock = AsyncMock()
        mock.__getitem__.return_value = AsyncMock()
        mock.admin.command = AsyncMock(return_value={"ok": 1})
        mock.close = MagicMock()
        return mock
    
    backend.database.AsyncIOMotorClient = capture_client
    try:
        await connect_to_mongo()
    finally:
        backend.database.AsyncIOMotorClient = original_client
    
    assert created_config.get("maxPoolSize") == settings.MONGODB_MAX_POOL_SIZE
    assert created_config.get("minPoolSize") == settings.MONGODB_MIN_POOL_SIZE
    assert created_config.get("serverSelectionTimeoutMS") == settings.MONGODB_SERVER_SELECTION_TIMEOUT_MS
    assert created_config.get("connectTimeoutMS") == settings.MONGODB_CONNECT_TIMEOUT_MS
    assert created_config.get("socketTimeoutMS") == settings.MONGODB_SOCKET_TIMEOUT_MS