import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from sse_starlette.sse import EventSourceResponse

from backend.config import settings
from backend.database import close_mongo_connection, get_db
from backend.exceptions import DatabaseUnavailableError
from backend.jobs import run_baseline_triage, run_llm_triage, run_scan
from backend.models import (
    FindingResponse,
    ReportFormat,
    ScanCreate,
    ScanProgress,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    SeverityLevel,
    TriageCompareResponse,
    TriageMode,
    TriageResult,
    TriageRunCreate,
    TriageRunResponse,
)

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup - no DB connect; lazy on first request
    yield
    # Shutdown
    await close_mongo_connection()


app = FastAPI(
    title="VibeShield API",
    description="Security scanner for AI-assisted/vibe-coded web apps",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(DatabaseUnavailableError)
async def database_unavailable_handler(request: Request, exc: DatabaseUnavailableError):
    return JSONResponse(
        status_code=503,
        content={"detail": "Database temporarily unavailable"},
    )


# ===================== SCAN ENDPOINTS =====================

@app.post("/api/scans", response_model=ScanResponse, status_code=202)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan."""
    db = await get_db()

    scan_data = ScanCreate(
        scan_id=uuid4(),
        target_url=str(request.url),
        max_pages=request.max_pages,
        max_depth=request.max_depth,
        timeout=request.timeout,
        allow_write_tests=request.allow_write_tests,
    )

    await db.scans.insert_one(scan_data.model_dump())

    background_tasks.add_task(run_scan, scan_data.scan_id, scan_data)

    return ScanResponse(
        scan_id=scan_data.scan_id,
        status=scan_data.status,
        progress=scan_data.progress,
        created_at=scan_data.created_at,
        updated_at=scan_data.updated_at,
        target_url=scan_data.target_url,
    )


@app.get("/api/scans", response_model=list[ScanResponse])
async def list_scans(
    status: ScanStatus | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List all scans with optional filtering."""
    db = await get_db()

    query = {}
    if status:
        query["status"] = status.value

    cursor = db.scans.find(query).sort("created_at", -1).skip(offset).limit(limit)
    scans = []
    async for doc in cursor:
        scans.append(ScanResponse(
            scan_id=UUID(doc["scan_id"]),
            status=ScanStatus(doc["status"]),
            progress=ScanProgress(**doc.get("progress", {})),
            created_at=doc["created_at"],
            updated_at=doc["updated_at"],
            target_url=doc["target_url"],
            error=doc.get("error"),
        ))
    return scans


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: Annotated[UUID, Path(...)]):
    """Get scan details by ID."""
    db = await get_db()
    doc = await db.scans.find_one({"scan_id": str(scan_id)})
    if not doc:
        raise HTTPException(404, "Scan not found")

    return ScanResponse(
        scan_id=UUID(doc["scan_id"]),
        status=ScanStatus(doc["status"]),
        progress=ScanProgress(**doc.get("progress", {})),
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
        target_url=doc["target_url"],
        error=doc.get("error"),
    )


@app.get("/api/scans/{scan_id}/progress")
async def scan_progress_stream(scan_id: Annotated[UUID, Path(...)]):
    """SSE stream for live scan progress."""
    db = await get_db()

    # Verify scan exists
    doc = await db.scans.find_one({"scan_id": str(scan_id)})
    if not doc:
        raise HTTPException(404, "Scan not found")

    async def event_generator():
        last_log_id = None
        while True:
            # Check for new progress logs
            cursor = db.progress_logs.find(
                {"scan_id": str(scan_id)}
            ).sort("timestamp", 1)

            if last_log_id:
                cursor = cursor.find({"_id": {"$gt": last_log_id}})

            async for log_doc in cursor:
                last_log_id = log_doc["_id"]
                yield {
                    "event": "progress",
                    "data": {
                        "timestamp": log_doc["timestamp"].isoformat(),
                        "level": log_doc["level"],
                        "message": log_doc["message"],
                        "stage": log_doc.get("stage"),
                    }
                }

            # Check if scan is complete
            scan_doc = await db.scans.find_one({"scan_id": str(scan_id)})
            if scan_doc and scan_doc["status"] in ("completed", "failed"):
                yield {
                    "event": "complete",
                    "data": {
                        "status": scan_doc["status"],
                        "error": scan_doc.get("error"),
                    }
                }
                break

            await asyncio.sleep(1)

    return EventSourceResponse(event_generator())


# ===================== FINDINGS ENDPOINTS =====================

@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingResponse])
async def get_findings(
    scan_id: Annotated[UUID, Path(...)],
    severity: SeverityLevel | None = None,
    check: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    """Get findings for a scan with optional filters."""
    db = await get_db()

    query = {"scan_id": str(scan_id)}
    if severity:
        query["severity"] = severity.value
    if check:
        query["check"] = check

    cursor = db.findings.find(query).skip(offset).limit(limit)
    findings = []
    async for doc in cursor:
        findings.append(FindingResponse(**doc))
    return findings


@app.get("/api/scans/{scan_id}/findings/stats")
async def get_findings_stats(scan_id: Annotated[UUID, Path(...)]):
    """Get finding statistics (count by severity/check)."""
    db = await get_db()

    pipeline = [
        {"$match": {"scan_id": str(scan_id)}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    severity_stats = {}
    async for doc in db.findings.aggregate(pipeline):
        severity_stats[doc["_id"]] = doc["count"]

    pipeline = [
        {"$match": {"scan_id": str(scan_id)}},
        {"$group": {"_id": "$check", "count": {"$sum": 1}}},
    ]
    check_stats = {}
    async for doc in db.findings.aggregate(pipeline):
        check_stats[doc["_id"]] = doc["count"]

    return {"by_severity": severity_stats, "by_check": check_stats}


# ===================== TRIAGE ENDPOINTS =====================

@app.post("/api/scans/{scan_id}/triage", response_model=TriageRunResponse, status_code=202)
async def start_triage(
    scan_id: Annotated[UUID, Path(...)],
    mode: Annotated[TriageMode, Query()] = TriageMode.BASELINE,
    background_tasks: BackgroundTasks = None,
):
    """Start a triage run (baseline or LLM)."""
    db = await get_db()

    # Verify scan exists and is completed
    scan = await db.scans.find_one({"scan_id": str(scan_id)})
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(400, f"Scan not completed (status: {scan['status']})")

    triage_data = TriageRunCreate(
        triage_id=uuid4(),
        scan_id=scan_id,
        mode=mode,
    )

    await db.triage_runs.insert_one(triage_data.model_dump())

    if mode == TriageMode.BASELINE:
        background_tasks.add_task(run_baseline_triage, scan_id, triage_data)
    else:
        background_tasks.add_task(run_llm_triage, scan_id, triage_data)

    return TriageRunResponse(
        triage_id=triage_data.triage_id,
        scan_id=triage_data.scan_id,
        mode=triage_data.mode,
        status=triage_data.status,
        results=[],
        created_at=triage_data.created_at,
    )


@app.get("/api/scans/{scan_id}/triage", response_model=list[TriageRunResponse])
async def list_triage_runs(scan_id: Annotated[UUID, Path(...)]):
    """List all triage runs for a scan."""
    db = await get_db()

    cursor = db.triage_runs.find({"scan_id": str(scan_id)}).sort("created_at", -1)
    runs = []
    async for doc in cursor:
        runs.append(TriageRunResponse(
            triage_id=UUID(doc["triage_id"]),
            scan_id=UUID(doc["scan_id"]),
            mode=TriageMode(doc["mode"]),
            status=doc["status"],
            results=[TriageResult(**r) for r in doc.get("results", [])],
            created_at=doc["created_at"],
            completed_at=doc.get("completed_at"),
            error=doc.get("error"),
        ))
    return runs


@app.get("/api/triage/{triage_id}", response_model=TriageRunResponse)
async def get_triage(triage_id: Annotated[UUID, Path(...)]):
    """Get triage run details by ID."""
    db = await get_db()
    doc = await db.triage_runs.find_one({"triage_id": str(triage_id)})
    if not doc:
        raise HTTPException(404, "Triage run not found")

    return TriageRunResponse(
        triage_id=UUID(doc["triage_id"]),
        scan_id=UUID(doc["scan_id"]),
        mode=TriageMode(doc["mode"]),
        status=doc["status"],
        results=[TriageResult(**r) for r in doc.get("results", [])],
        created_at=doc["created_at"],
        completed_at=doc.get("completed_at"),
        error=doc.get("error"),
    )


@app.get("/api/scans/{scan_id}/triage/compare", response_model=TriageCompareResponse)
async def compare_triage(scan_id: Annotated[UUID, Path(...)]):
    """Compare baseline vs LLM triage results."""
    db = await get_db()

    baseline_run = await db.triage_runs.find_one(
        {"scan_id": str(scan_id), "mode": "baseline"},
        sort=[("created_at", -1)]
    )
    llm_run = await db.triage_runs.find_one(
        {"scan_id": str(scan_id), "mode": "llm"},
        sort=[("created_at", -1)]
    )

    baseline_results = [TriageResult(**r) for r in baseline_run.get("results", [])] if baseline_run else []
    llm_results = [TriageResult(**r) for r in llm_run.get("results", [])] if llm_run else []

    baseline_ids = {r.finding_id for r in baseline_results}
    llm_ids = {r.finding_id for r in llm_results}

    # Find changed priorities
    changed = []
    for b in baseline_results:
        for l in llm_results:
            if b.finding_id == l.finding_id and b.revised_priority != l.revised_priority:
                changed.append({
                    "finding_id": b.finding_id,
                    "baseline_priority": b.revised_priority,
                    "llm_priority": l.revised_priority,
                })

    return TriageCompareResponse(
        scan_id=scan_id,
        baseline=baseline_results,
        llm=llm_results,
        baseline_only=list(baseline_ids - llm_ids),
        llm_only=list(llm_ids - baseline_ids),
        changed_priority=changed,
    )


@app.post("/api/triage/{triage_id}/regenerate", response_model=TriageRunResponse, status_code=202)
async def regenerate_triage(
    triage_id: Annotated[UUID, Path(...)],
    finding_id: Annotated[str, Query(...)],
    background_tasks: BackgroundTasks = None,
):
    """Regenerate triage for a single finding (LLM only)."""
    db = await get_db()

    triage = await db.triage_runs.find_one({"triage_id": str(triage_id)})
    if not triage:
        raise HTTPException(404, "Triage run not found")
    if triage["mode"] != "llm":
        raise HTTPException(400, "Can only regenerate LLM triage runs")

    # Find the specific finding
    finding_doc = await db.findings.find_one({"scan_id": triage["scan_id"], "id": finding_id})
    if not finding_doc:
        raise HTTPException(404, "Finding not found")

    # For now, re-run full LLM triage (in Phase 2, implement per-finding regen)
    # This is a placeholder - would need orchestrator modification for single finding
    background_tasks.add_task(run_llm_triage, UUID(triage["scan_id"]), TriageRunCreate(
        triage_id=uuid4(),
        scan_id=UUID(triage["scan_id"]),
        mode=TriageMode.LLM,
    ))

    return TriageRunResponse(
        triage_id=triage_id,
        scan_id=UUID(triage["scan_id"]),
        mode=TriageMode.LLM,
        status="running",
        results=[],
        created_at=datetime.now(UTC),
    )


# ===================== REPORT ENDPOINTS =====================

@app.get("/api/scans/{scan_id}/report")
async def get_report(
    scan_id: Annotated[UUID, Path(...)],
    format: Annotated[ReportFormat, Query()] = ReportFormat.PLAIN,
):
    """Get scan report in plain text or JSON format."""
    db = await get_db()

    scan = await db.scans.find_one({"scan_id": str(scan_id)})
    if not scan:
        raise HTTPException(404, "Scan not found")

    if format == ReportFormat.PLAIN:
        report = scan.get("plain_report", "Report not available")
        return PlainTextResponse(report, media_type="text/plain")
    elif format == ReportFormat.JSON:
        report = scan.get("json_report", {})
        return report
    else:  # BOTH
        plain = scan.get("plain_report", "Report not available")
        json_report = scan.get("json_report", {})
        return {
            "plain": plain,
            "json": json_report,
        }


# ===================== KB CONTEXT ENDPOINTS (Phase 2) =====================

@app.get("/api/triage/kb-context")
async def get_kb_context(
    finding_id: Annotated[str, Query(...)],
    scan_id: Annotated[UUID, Query(...)],
):
    """Get KB context used for a finding's triage (Phase 2)."""
    from vibeshield.models.finding import Evidence, Finding
    from vibeshield.models.finding import SeverityLevel as CoreSeverityLevel
    from vibeshield.triage.context.retriever import get_retriever

    db = await get_db()

    finding_doc = await db.findings.find_one({"scan_id": str(scan_id), "id": finding_id})
    if not finding_doc:
        raise HTTPException(404, "Finding not found")

    evidence = Evidence(
        url=finding_doc["evidence"]["url"],
        snippet=finding_doc["evidence"]["snippet"],
        matched_pattern=finding_doc["evidence"].get("matched_pattern"),
        request_headers=finding_doc["evidence"].get("request_headers", {}),
        response_headers=finding_doc["evidence"].get("response_headers", {}),
        response_status=finding_doc["evidence"].get("response_status"),
    )
    finding = Finding(
        id=finding_doc["id"],
        check=finding_doc["check"],
        title=finding_doc["title"],
        severity=CoreSeverityLevel(finding_doc["severity"]),
        score=finding_doc["score"],
        impact=finding_doc["impact"],
        likelihood=finding_doc["likelihood"],
        wstg_id=finding_doc.get("wstg_id"),
        attck_ids=finding_doc.get("attck_ids", []),
        evidence=evidence,
        confidence=finding_doc["confidence"],
        remediation=finding_doc["remediation"],
        references=finding_doc.get("references", []),
    )

    retriever = get_retriever()
    context = retriever.retrieve(finding)

    return {
        "finding_id": finding_id,
        "context": [
            {"topic": c.topic, "content": c.content, "source_file": c.source_file}
            for c in context
        ],
    }


# ===================== HEALTH =====================

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "vibeshield-api"}