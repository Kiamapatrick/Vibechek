import logging
import re
from typing import ClassVar

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient
from vibeshield.utils.patterns import DEBUG_ENDPOINTS

log = logging.getLogger(__name__)


class DebugModeCheck(BaseCheck):
    name = "debug_mode"
    description = "Detects debug mode, verbose errors, and exposed debug endpoints"

    ERROR_PATTERNS: ClassVar[list[tuple[re.Pattern, str]]] = [
        (re.compile(r"(?i)stack trace|traceback|at\s+\w+\.\w+\("), "Stack trace in response"),
        (re.compile(r"(?i)file\s+\"[^\"]+\",\s+line\s+\d+"), "Source code path disclosure"),
        (re.compile(r"(?i)exception|error\s+in\s+/"), "Verbose error message"),
        (re.compile(r"(?i)debug\s*=\s*true|NEXT_DEBUG"), "Debug flag enabled"),
        (re.compile(r"(?i)webpack|__webpack_require__|module\.exports"), "Source map / bundle internals"),
    ]

    DEBUG_ENDPOINTS: ClassVar[list[str]] = DEBUG_ENDPOINTS

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []

        findings.extend(await self._check_verbose_errors(recon, http))
        findings.extend(await self._check_debug_endpoints(recon, http))
        findings.extend(self._check_source_maps(recon))
        findings.extend(self._check_debug_headers(recon))

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    async def _check_verbose_errors(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        test_paths = ["/nonexistent-page-12345", "/api/nonexistent-12345"]

        for path in test_paths:
            url = f"{recon.base_url}{path}"
            try:
                resp = await http.get(url, timeout=5.0)
                if resp.status_code >= 400:
                    for pattern, desc in self.ERROR_PATTERNS:
                        if pattern.search(resp.text):
                            evidence = Evidence(
                                url=url,
                                snippet=resp.text[:500],
                                response_status=resp.status_code,
                                response_headers=dict(resp.headers),
                            )
                            findings.append(Finding(
                                check=self.name,
                                title=f"Verbose Error Page: {desc}",
                                severity=SeverityLevel.MEDIUM,
                                score=3 * 3,
                                impact=3,
                                likelihood=3,
                                wstg_id="",
                                attck_ids=[],
                                evidence=evidence,
                                confidence=0.85,
                                remediation=(
                                    "Disable debug mode in production. "
                                    "Next.js: Set NODE_ENV=production and remove NEXT_DEBUG. "
                                    "Express: Set NODE_ENV=production. "
                                    "Django: DEBUG=False. "
                                    "Use custom error pages."
                                ),
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Bypassing_Authorization_Schema",
                                ],
                            ))
                            break
            except Exception:
                log.warning("Verbose error check failed", exc_info=True)
                continue
        return findings

    async def _check_debug_endpoints(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        for endpoint in self.DEBUG_ENDPOINTS:
            url = f"{recon.base_url}{endpoint}"
            try:
                resp = await http.get(url, timeout=3.0)
                if resp.status_code == 200:
                    evidence = Evidence(
                        url=url,
                        snippet=resp.text[:300],
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                    )
                    findings.append(Finding(
                        check=self.name,
                        title=f"Exposed Debug Endpoint: {endpoint}",
                        severity=SeverityLevel.HIGH,
                        score=4 * 3,
                        impact=4,
                        likelihood=3,
                        wstg_id="",
                        attck_ids=[],
                        evidence=evidence,
                        confidence=0.8,
                        remediation=(
                            f"Remove or protect {endpoint} in production. "
                            "Add authentication middleware or remove debug routes entirely."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
                        ],
                    ))
            except Exception:
                log.warning("Debug endpoint check failed", exc_info=True)
                continue
        return findings

    def _check_source_maps(self, recon: ReconData) -> list[Finding]:
        findings: list[Finding] = []
        for page in recon.pages:
            for script in page.scripts:
                if script.endswith(".js"):
                    map_url = script + ".map"
                    if map_url not in [f.evidence.url for f in findings]:
                        findings.append(self._create_source_map_finding(map_url))
        return findings

    def _create_source_map_finding(self, map_url: str) -> Finding:
        evidence = Evidence(
            url=map_url,
            snippet="Source map file (.map) potentially accessible",
            matched_pattern=".map",
        )
        return Finding(
            check=self.name,
            title="Accessible JavaScript Source Map",
            severity=SeverityLevel.LOW,
            score=2 * 2,
            impact=2,
            likelihood=2,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.5,
            remediation="Disable source map generation in production builds. Next.js: Set productionBrowserSourceMaps: false in next.config.js. Webpack: Set devtool: false in production.",
            references=[
                "https://webpack.js.org/configuration/devtool/",
                "https://nextjs.org/docs/architecture/nextjs-compiler#source-maps",
            ],
        )

    def _check_debug_headers(self, recon: ReconData) -> list[Finding]:
        findings = []
        for page in recon.pages:
            headers = {k.lower(): v for k, v in page.headers.items()}
            debug_headers = []
            if "x-debug-token" in headers:
                debug_headers.append(f"X-Debug-Token: {headers['x-debug-token']}")
            if "x-drupal-cache" in headers:
                debug_headers.append(f"X-Drupal-Cache: {headers['x-drupal-cache']}")
            if "x-powered-by" in headers and "debug" in headers["x-powered-by"].lower():
                debug_headers.append(f"X-Powered-By: {headers['x-powered-by']}")

            if debug_headers:
                evidence = Evidence(
                    url=page.url,
                    snippet="; ".join(debug_headers),
                    response_status=page.status_code,
                    response_headers=page.headers,
                )
                findings.append(Finding(
                    check=self.name,
                    title="Debug Headers Present",
                    severity=SeverityLevel.INFO,
                    score=1 * 2,
                    impact=1,
                    likelihood=2,
                    wstg_id="",
                    attck_ids=[],
                    evidence=evidence,
                    confidence=0.7,
                    remediation="Remove debug headers in production. Check framework configuration for debug header emission.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                    ],
                ))
        return findings