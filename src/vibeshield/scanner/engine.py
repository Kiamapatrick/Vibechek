import logging
import time
from datetime import UTC, datetime

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
    ):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.allow_write_tests = allow_write_tests

    async def run(self) -> tuple[PlainReport, JSONReport]:
        start_time = time.time()

        async with HTTPClient(timeout=self.timeout) as http:
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
            # Pass allow_write_tests to checks that declare it
            if hasattr(check, "allow_write_tests"):
                check.allow_write_tests = self.allow_write_tests
            try:
                findings = await check.run(recon, http)
                all_findings.extend(findings)
            except Exception:
                log.warning("Check failed, continuing", exc_info=True)

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