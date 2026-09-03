from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
import logging
from typing import Optional

from backend.config import settings

log = logging.getLogger(__name__)

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo() -> AsyncIOMotorDatabase:
    global _client, _db
    if _client is not None:
        return _db

    try:
        _client = AsyncIOMotorClient(settings.MONGODB_URI)
        _db = _client[settings.MONGODB_DB]
        # Test connection
        await _client.admin.command("ping")
        log.info("Connected to MongoDB: %s", settings.MONGODB_DB)

        # Create indexes
        await _db.scans.create_index([("created_at", DESCENDING)])
        await _db.scans.create_index([("status", ASCENDING)])
        await _db.findings.create_index([("scan_id", ASCENDING)])
        await _db.findings.create_index([("severity", ASCENDING)])
        await _db.triage_runs.create_index([("scan_id", ASCENDING)])
        await _db.triage_runs.create_index([("created_at", DESCENDING)])
        await _db.progress_logs.create_index([("scan_id", ASCENDING), ("timestamp", ASCENDING)])

        return _db
    except ConnectionFailure as e:
        log.error("Failed to connect to MongoDB: %s", e)
        raise


async def close_mongo_connection() -> None:
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        log.info("Closed MongoDB connection")


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not initialized. Call connect_to_mongo() first.")
    return _db