import asyncio
import logging
import traceback
from datetime import datetime
from typing import Optional
from uuid import UUID

from backend.database import get_db
from backend.models import (
    ScanCreate, ScanStatus, ScanProgress,
    FindingResponse, SeverityLevel, TriageRunCreate,
    TriageResult, TriageSource, TriageMode, ProgressLog
)

log = logging.getLogger(__name__)


async def log_progress(scan_id: UUID, level: str, message: str, stage: Optional[str] = None) -> None:
    db = get_db()
    log_entry = ProgressLog(
        scan_id=scan_id,
        level=level,
        message=message,
        stage=stage
    )
    await db.progress_logs.insert_one(log_entry.model_dump())
    log.info("[%s] %s: %s", scan_id, level.upper(), message)


async def update_scan_status(
    scan_id: UUID,
    status: ScanStatus,
    progress: Optional[ScanProgress] = None,
    error: Optional[str] = None
) -> None:
    db = get_db()
    update = {"status": status.value, "updated_at": datetime.utcnow()}
    if progress:
        update["progress"] = progress.model_dump()
    if error:
        update["error"] = error
    await db.scans.update_one({"scan_id": str(scan_id)}, {"$set": update})
    await log_progress(scan_id, "info", f"Status changed to {status.value}")


async def run_scan(scan_id: UUID, scan_data: ScanCreate) -> None:
    """Background task to run the scanner."""
    from vibeshield.scanner.engine import ScannerEngine
    from vibeshield.reporting.plain import PlainReporter
    from vibeshield.reporting.json import JSONReporter
    from vibeshield.models.finding import Finding, Evidence, SeverityLevel as CoreSeverityLevel

    db = get_db()

    try:
        await update_scan_status(scan_id, ScanStatus.RUNNING)
        await log_progress(scan_id, "info", f"Starting scan of {scan_data.target_url}", "scan")

        engine = ScannerEngine(
            target_url=scan_data.target_url,
            max_depth=scan_data.max_depth,
            max_pages=scan_data.max_pages,
            timeout=scan_data.timeout,
            allow_write_tests=scan_data.allow_write_tests,
        )

        # Progress callback would need ScannerEngine modification
        # For now, run and log at key points
        await log_progress(scan_id, "info", "Running reconnaissance...", "recon")

        plain_report, json_report = await engine.run()

        await log_progress(scan_id, "info", f"Scan complete. Found {len(json_report.findings)} findings", "scan")

        # Convert findings to our API models
        findings = []
        for f in json_report.findings:
            evidence = Evidence(
                url=f.evidence.url,
                snippet=f.evidence.snippet,
                matched_pattern=f.evidence.matched_pattern,
                request_headers=f.evidence.request_headers,
                response_headers=f.evidence.response_headers,
                response_status=f.evidence.response_status,
            )
            finding = FindingResponse(
                id=f.id,
                check=f.check,
                title=f.title,
                severity=SeverityLevel(f.severity.value),
                score=f.score,
                impact=f.impact,
                likelihood=f.likelihood,
                wstg_id=f.wstg_id,
                attck_ids=f.attck_ids,
                evidence=evidence,
                confidence=f.confidence,
                remediation=f.remediation,
                references=f.references,
                scan_id=scan_id,
            )
            findings.append(finding.model_dump())

        # Store findings
        if findings:
            await db.findings.insert_many(findings)

        # Store reports
        await db.scans.update_one(
            {"scan_id": str(scan_id)},
            {
                "$set": {
                    "plain_report": PlainReporter.generate(plain_report),
                    "json_report": json_report.to_dict(),
                    "status": ScanStatus.COMPLETED.value,
                    "updated_at": datetime.utcnow(),
                    "progress": ScanProgress(
                        pages_crawled=plain_report.scan_metadata.pages_crawled,
                        findings_found=len(findings)
                    ).model_dump()
                }
            }
        )

        await log_progress(scan_id, "info", "Scan completed successfully", "scan")

    except Exception as e:
        log.exception("Scan %s failed: %s", scan_id, e)
        await update_scan_status(scan_id, ScanStatus.FAILED, error=str(e))
        await log_progress(scan_id, "error", f"Scan failed: {e}", "scan")


async def run_baseline_triage(scan_id: UUID, triage_data: TriageRunCreate) -> None:
    """Background task to run baseline triage."""
    from vibeshield.triage.baseline import baseline_rank
    from vibeshield.models.finding import Finding, Evidence, SeverityLevel as CoreSeverityLevel

    db = get_db()

    try:
        await log_progress(scan_id, "info", "Starting baseline triage...", "triage")

        # Load findings
        findings_cursor = db.findings.find({"scan_id": str(scan_id)})
        findings = []
        async for doc in findings_cursor:
            evidence = Evidence(
                url=doc["evidence"]["url"],
                snippet=doc["evidence"]["snippet"],
                matched_pattern=doc["evidence"].get("matched_pattern"),
                request_headers=doc["evidence"].get("request_headers", {}),
                response_headers=doc["evidence"].get("response_headers", {}),
                response_status=doc["evidence"].get("response_status"),
            )
            finding = Finding(
                id=doc["id"],
                check=doc["check"],
                title=doc["title"],
                severity=CoreSeverityLevel(doc["severity"]),
                score=doc["score"],
                impact=doc["impact"],
                likelihood=doc["likelihood"],
                wstg_id=doc.get("wstg_id"),
                attck_ids=doc.get("attck_ids", []),
                evidence=evidence,
                confidence=doc["confidence"],
                remediation=doc["remediation"],
                references=doc.get("references", []),
            )
            findings.append(finding)

        if not findings:
            await log_progress(scan_id, "warning", "No findings to triage", "triage")
            await db.triage_runs.update_one(
                {"triage_id": str(triage_data.triage_id)},
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow(),
                        "results": []
                    }
                }
            )
            return

        await log_progress(scan_id, "info", f"Triaging {len(findings)} findings with baseline", "triage")

        # Run baseline triage
        triage_results = baseline_rank(findings)

        # Convert to API models
        results = []
        for r in triage_results:
            result = TriageResult(
                finding_id=r.finding.id,
                finding_title=r.finding.title,
                explanation=r.explanation,
                exploitability=r.exploitability,
                fix=r.fix,
                revised_priority=r.revised_priority,
                source=TriageSource(r.source),
                prompt_version=r.prompt_version,
                original_severity=SeverityLevel(r.finding.severity.value),
            )
            results.append(result.model_dump())

        # Store triage run
        await db.triage_runs.update_one(
            {"triage_id": str(triage_data.triage_id)},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": datetime.utcnow(),
                    "results": results
                }
            }
        )

        await log_progress(scan_id, "info", f"Baseline triage completed: {len(results)} results", "triage")

    except Exception as e:
        log.exception("Baseline triage %s failed: %s", triage_data.triage_id, e)
        await db.triage_runs.update_one(
            {"triage_id": str(triage_data.triage_id)},
            {
                "$set": {
                    "status": "failed",
                    "completed_at": datetime.utcnow(),
                    "error": str(e)
                }
            }
        )
        await log_progress(scan_id, "error", f"Baseline triage failed: {e}", "triage")


async def run_llm_triage(scan_id: UUID, triage_data: TriageRunCreate) -> None:
    """Background task to run LLM triage with streaming support."""
    from vibeshield.triage.orchestrator import run_triage
    from vibeshield.triage.ingest import load_report
    from vibeshield.models.report import JSONReport, ScanMetadata, FingerprintResult, Summary
    from vibeshield.models.finding import Finding, Evidence, SeverityLevel as CoreSeverityLevel
    import json
    import tempfile
    from pathlib import Path

    db = get_db()

    try:
        await log_progress(scan_id, "info", "Starting LLM triage...", "triage")

        # Load findings
        findings_cursor = db.findings.find({"scan_id": str(scan_id)})
        findings = []
        async for doc in findings_cursor:
            evidence = Evidence(
                url=doc["evidence"]["url"],
                snippet=doc["evidence"]["snippet"],
                matched_pattern=doc["evidence"].get("matched_pattern"),
                request_headers=doc["evidence"].get("request_headers", {}),
                response_headers=doc["evidence"].get("response_headers", {}),
                response_status=doc["evidence"].get("response_status"),
            )
            finding = Finding(
                id=doc["id"],
                check=doc["check"],
                title=doc["title"],
                severity=CoreSeverityLevel(doc["severity"]),
                score=doc["score"],
                impact=doc["impact"],
                likelihood=doc["likelihood"],
                wstg_id=doc.get("wstg_id"),
                attck_ids=doc.get("attck_ids", []),
                evidence=evidence,
                confidence=doc["confidence"],
                remediation=doc["remediation"],
                references=doc.get("references", []),
            )
            findings.append(finding)

        if not findings:
            await log_progress(scan_id, "warning", "No findings to triage", "triage")
            await db.triage_runs.update_one(
                {"triage_id": str(triage_data.triage_id)},
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow(),
                        "results": []
                    }
                }
            )
            return

        await log_progress(scan_id, "info", f"Triaging {len(findings)} findings with LLM", "triage")

        # Run LLM triage
        triage_results = run_triage(findings)

        # Convert to API models
        results = []
        for r in triage_results:
            result = TriageResult(
                finding_id=r.finding.id,
                finding_title=r.finding.title,
                explanation=r.explanation,
                exploitability=r.exploitability,
                fix=r.fix,
                revised_priority=r.revised_priority,
                source=TriageSource(r.source),
                prompt_version=r.prompt_version,
                original_severity=SeverityLevel(r.finding.severity.value),
            )
            results.append(result.model_dump())

        # Store triage run
        await db.triage_runs.update_one(
            {"triage_id": str(triage_data.triage_id)},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": datetime.utcnow(),
                    "results": results
                }
            }
        )

        await log_progress(scan_id, "info", f"LLM triage completed: {len(results)} results", "triage")

    except Exception as e:
        log.exception("LLM triage %s failed: %s", triage_data.triage_id, e)
        await db.triage_runs.update_one(
            {"triage_id": str(triage_data.triage_id)},
            {
                "$set": {
                    "status": "failed",
                    "completed_at": datetime.utcnow(),
                    "error": str(e)
                }
            }
        )
        await log_progress(scan_id, "error", f"LLM triage failed: {e}", "triage")