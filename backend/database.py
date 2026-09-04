import asyncio
import logging
import time

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from backend.config import settings
from backend.exceptions import DatabaseUnavailableError

log = logging.getLogger(__name__)

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None
_last_connection_failure: float = 0.0


async def _create_client() -> AsyncIOMotorClient:
    return AsyncIOMotorClient(
        settings.MONGODB_URI,
        maxPoolSize=settings.MONGODB_MAX_POOL_SIZE,
        minPoolSize=settings.MONGODB_MIN_POOL_SIZE,
        serverSelectionTimeoutMS=settings.MONGODB_SERVER_SELECTION_TIMEOUT_MS,
        connectTimeoutMS=settings.MONGODB_CONNECT_TIMEOUT_MS,
        socketTimeoutMS=settings.MONGODB_SOCKET_TIMEOUT_MS,
    )


async def _connect_with_retry() -> AsyncIOMotorDatabase:
    global _client, _db, _last_connection_failure
    last_exception = None
    for attempt in range(settings.MONGODB_MAX_RETRIES):
        try:
            _client = await _create_client()
            _db = _client[settings.MONGODB_DB]
            await _client.admin.command("ping")
            log.info("Connected to MongoDB: %s", settings.MONGODB_DB)
            _last_connection_failure = 0.0
            return _db
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            last_exception = e
            if attempt < settings.MONGODB_MAX_RETRIES - 1:
                delay = settings.MONGODB_RETRY_BASE_DELAY * (2 ** attempt)
                log.warning("MongoDB connection attempt %d failed: %s. Retrying in %.1fs...", 
                           attempt + 1, e, delay)
                await asyncio.sleep(delay)
            else:
                log.error("All %d MongoDB connection attempts failed", settings.MONGODB_MAX_RETRIES)
    _last_connection_failure = time.time()
    raise DatabaseUnavailableError(f"Failed to connect to MongoDB after {settings.MONGODB_MAX_RETRIES} attempts: {last_exception}") from last_exception


async def _create_indexes(db: AsyncIOMotorDatabase) -> None:
    index_specs = [
        ("scans", [("created_at", DESCENDING)]),
        ("scans", [("status", ASCENDING)]),
        ("findings", [("scan_id", ASCENDING)]),
        ("findings", [("severity", ASCENDING)]),
        ("triage_runs", [("scan_id", ASCENDING)]),
        ("triage_runs", [("created_at", DESCENDING)]),
        ("progress_logs", [("scan_id", ASCENDING), ("timestamp", ASCENDING)]),
    ]
    for collection_name, keys in index_specs:
        try:
            await db[collection_name].create_index(keys)
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to create index on %s.%s: %s", collection_name, keys, e)


async def connect_to_mongo() -> AsyncIOMotorDatabase:
    """Initialize connection. Called lazily by get_db()."""
    global _db
    if _db is not None:
        return _db
    _db = await _connect_with_retry()
    await _create_indexes(_db)
    return _db


async def close_mongo_connection() -> None:
    global _client, _db, _last_connection_failure
    if _client:
        _client.close()
        _client = None
        _db = None
        _last_connection_failure = 0.0
        log.info("Closed MongoDB connection")


async def get_db() -> AsyncIOMotorDatabase:
    global _db, _last_connection_failure  # noqa: PLW0602
    if _db is not None:
        return _db

    # Cooldown: if we recently failed, don't hammer the DB
    if _last_connection_failure > 0:
        elapsed = time.time() - _last_connection_failure
        if elapsed < settings.MONGODB_FAILURE_COOLDOWN_SECONDS:
            remaining = settings.MONGODB_FAILURE_COOLDOWN_SECONDS - elapsed
            log.debug("MongoDB connection cooldown active (%.1fs remaining)", remaining)
            raise DatabaseUnavailableError("Database temporarily unavailable")

    return await connect_to_mongo()