import pytest
from pymongo.errors import ServerSelectionTimeoutError
from backend.database import connect_to_mongo, close_mongo_connection, get_db
from backend.exceptions import DatabaseUnavailableError
from backend.config import settings
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_get_db_lazy_connects(mock_motor_client, mongomock_db):
    await close_mongo_connection()
    db = await connect_to_mongo()
    assert db is mongomock_db
    mock_motor_client.admin.command.assert_awaited_with("ping")
    db2 = get_db()
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
async def test_close_mongo_connection_resets_state(mock_motor_client, mongomock_db):
    await close_mongo_connection()
    db = await connect_to_mongo()
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