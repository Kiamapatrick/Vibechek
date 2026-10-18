import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from vibeshield.config import settings
from vibeshield.models.finding import Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.models.report import JSONReport, PlainReport, ScanMetadata, Summary
from vibeshield.scanner.checks import ALL_CHECKS
from vibeshield.scanner.recon import Reconnaissance
from vibeshield.utils.http import HTTPClient

log = logging.getLogger(__name__)


class ScannerEngine:
    def __init__(
        self,
        target_url: str,
        max_depth: int = settings.DEFAULT_MAX_DEPTH,
        max_pages: int = settings.DEFAULT_MAX_PAGES,
        timeout: float = settings.DEFAULT_TIMEOUT,
        allow_write_tests: bool = False,
        allow_private_targets: bool = False,
        progress_callback: Callable[[str, dict[str, Any]], Any] | None = None,
    ):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.allow_write_tests = allow_write_tests
        self.allow_private_targets = allow_private_targets
        self.progress_callback = progress_callback

    async def _emit_progress(self, stage: str, data: dict[str, Any]) -> None:
        """Emit progress event if callback is registered."""
        if self.progress_callback:
            try:
                await self.progress_callback(stage, data)
            except Exception:
                log.warning("Progress callback failed", exc_info=True)

    async def run(self) -> tuple[PlainReport, JSONReport]:
        start_time = time.time()

        await self._emit_progress("recon_start", {"target_url": self.target_url})

        async with HTTPClient(timeout=self.timeout, allow_private_targets=self.allow_private_targets) as http:
            recon = await self._run_reconnaissance(http)
            findings = await self._run_checks(recon, http)

        duration_ms = int((time.time() - start_time) * 1000)

        for f in findings:
            if not f.wstg_id:
                f.severity, f.score = self._calculate_severity(f)

        findings.sort(key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            -f.score,
        ))

        summary = Summary.from_findings(findings)

        scan_metadata = ScanMetadata(
            target=self.target_url,
            timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            version=settings.VERSION,
            duration_ms=duration_ms,
            crawl_depth=self.max_depth,
            max_pages=self.max_pages,
            pages_crawled=len(recon.pages),
            checks_run=[check.__name__ for check in ALL_CHECKS],
        )

        await self._emit_progress("scan_complete", {
            "pages_crawled": len(recon.pages),
            "findings_found": len(findings),
        })

        json_report = JSONReport(
            scan_metadata=scan_metadata,
            fingerprint=recon.fingerprint,
            findings=findings,
            summary=summary,
        )

        plain_report = PlainReport(
            scan_metadata=scan_metadata,
            fingerprint=recon.fingerprint,
            findings=findings,
            summary=summary,
        )

        return plain_report, json_report

    async def _run_reconnaissance(self, http: HTTPClient) -> ReconData:
        recon = Reconnaissance(
            target_url=self.target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
        )
        return await recon.run(http)

    async def _run_checks(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        all_findings = []

        for check_class in ALL_CHECKS:
            check = check_class()  # type: ignore
            check_name = check.__class__.__name__
            # Pass allow_write_tests to checks that declare it
            if hasattr(check, "allow_write_tests"):
                check.allow_write_tests = self.allow_write_tests
            try:
                await self._emit_progress("check_start", {"check": check_name})
                findings = await check.run(recon, http)
                await self._emit_progress("check_complete", {
                    "check": check_name,
                    "findings_found": len(findings),
                })
                all_findings.extend(findings)
            except Exception:
                log.warning("Check failed, continuing", exc_info=True)
                await self._emit_progress("check_error", {"check": check_name})

        return all_findings

    def _calculate_severity(self, finding: Finding) -> tuple[SeverityLevel, int]:
        from vibeshield.scanner.scoring import calculate_severity
        return calculate_severity(finding.impact, finding.likelihood)


SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}