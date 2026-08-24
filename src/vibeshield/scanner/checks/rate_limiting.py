import asyncio
import logging
import re
from typing import ClassVar

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient

log = logging.getLogger(__name__)


class RateLimitingCheck(BaseCheck):
    name = "rate_limiting"
    description = "Detects missing rate limiting on authentication endpoints"

    AUTH_PATH_PATTERNS: ClassVar[list[str]] = [
        r"/api/auth/",
        r"/auth/",
        r"/login",
        r"/signup",
        r"/register",
        r"/signin",
        r"/password",
        r"/reset",
        r"/forgot",
        r"/verify",
        r"/magic",
        r"/auth/v1/",
    ]

    TEST_ATTEMPTS = 5

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        auth_endpoints = self._identify_auth_endpoints(recon)

        for endpoint in auth_endpoints:
            finding = await self._test_rate_limiting(endpoint, recon, http)
            if finding:
                findings.append(finding)

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    # Denylist patterns for endpoints that should NOT be rate-limit tested
    # (POSTing to these could create accounts, send reset emails, etc.)
    DENYLIST_PATTERNS: ClassVar[list[str]] = [
        r"signup",
        r"register",
        r"create.?account",
        r"password.*reset",
        r"forgot",
    ]

    def _identify_auth_endpoints(self, recon: ReconData) -> list[str]:
        endpoints = set()

        for page in recon.pages:
            for form in page.forms:
                action = form.get("action", "")
                if action and any(re.search(p, action) for p in self.AUTH_PATH_PATTERNS):
                    if action.startswith("/"):
                        action = f"{recon.base_url}{action}"
                    endpoints.add(action)

            for link in page.links:
                if any(re.search(p, link) for p in self.AUTH_PATH_PATTERNS):
                    if link.startswith("/"):
                        link = f"{recon.base_url}{link}"
                    endpoints.add(link)

        for ep in recon.get_api_endpoints():
            if any(re.search(p, ep) for p in self.AUTH_PATH_PATTERNS):
                endpoints.add(ep)

        # Filter out endpoints matching denylist patterns (signup, register, password reset, etc.)
        deny_patterns = self.DENYLIST_PATTERNS
        filtered = [
            ep for ep in endpoints
            if ep.startswith(recon.base_url)
            and not any(re.search(p, ep, re.IGNORECASE) for p in deny_patterns)
        ]
        return list(set(filtered))[:10]

    async def _test_rate_limiting(self, url: str, recon: ReconData, http: HTTPClient) -> Finding | None:
        results = []

        for i in range(self.TEST_ATTEMPTS):
            try:
                resp = await http.post(
                    url,
                    data={"email": f"test{i}@example.com", "password": "test123"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=5.0,
                )
                results.append({
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "text": resp.text[:200],
                })
            except Exception:
                log.warning("Rate limit test request failed", exc_info=True)
                results.append({"error": "network_error"})

            await asyncio.sleep(0.1)

        rate_limited = any(
            r.get("status") == 429 or
            "retry-after" in {k.lower(): v for k, v in r.get("headers", {}).items()}
            for r in results
        )

        if rate_limited:
            return None

        successful = sum(1 for r in results if r.get("status", 0) in (200, 201, 302, 401, 403, 422))
        if successful < self.TEST_ATTEMPTS * 0.6:
            return None

        evidence = Evidence(
            url=url,
            snippet=f"{successful}/{self.TEST_ATTEMPTS} requests succeeded without rate limiting",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            response_headers=results[-1].get("headers", {}) if results else {},
            response_status=results[-1].get("status") if results else None,
        )

        return Finding(
            check=self.name,
            title=f"No Rate Limiting on Auth Endpoint: {url.replace(recon.base_url, '')}",
            severity=SeverityLevel.HIGH,
            score=4 * 4,
            impact=4,
            likelihood=4,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.8,
            remediation=(
                "Implement rate limiting on auth endpoints. "
                "Next.js: Use @upstash/ratelimit or custom middleware. "
                "Express: Use express-rate-limit. "
                "Nginx: limit_req_zone. "
                "Supabase: Enable rate limiting in dashboard. "
                "Recommended: 5 requests/minute for login, 10/hour for signup."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_Authentication_Schema",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Password_Guessing",
            ],
        )