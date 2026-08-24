from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient


class CORSCheck(BaseCheck):
    name = "cors"
    description = "Detects permissive CORS configurations allowing unauthorized cross-origin requests"

    EVIL_ORIGIN = "https://evil.com"

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        endpoints = self._get_test_endpoints(recon)

        for endpoint in endpoints:
            finding = await self._test_cors(endpoint, recon, http)
            if finding:
                findings.append(finding)

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    def _get_test_endpoints(self, recon: ReconData) -> list[str]:
        endpoints = set()
        for page in recon.pages:
            for link in page.links:
                if "/api/" in link or "/graphql" in link or "/rest/" in link:
                    endpoints.add(link)
        endpoints.update(recon.get_api_endpoints())

        filtered = []
        for ep in endpoints:
            if ep.startswith("/"):
                ep = f"{recon.base_url}{ep}"
            if ep.startswith(recon.base_url):
                filtered.append(ep)
        return list(set(filtered))[:20]

    async def _test_cors(self, url: str, recon: ReconData, http: HTTPClient) -> Finding | None:
        try:
            resp = await http.options(
                url,
                headers={
                    "Origin": self.EVIL_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Content-Type",
                },
                timeout=5.0,
            )
        except Exception:
            try:
                resp = await http.get(
                    url,
                    headers={"Origin": self.EVIL_ORIGIN},
                    timeout=5.0,
                )
            except Exception:
                return None

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        if not acao:
            return None

        is_wildcard = acao == "*"
        reflects_evil = acao == self.EVIL_ORIGIN

        if not (is_wildcard or reflects_evil):
            return None

        if is_wildcard and acac == "true":
            return self._create_finding(
                url, acao, acac, resp,
                "CORS allows credentials with wildcard origin (*)",
                SeverityLevel.CRITICAL, 5, 4,
                "Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. "
                "Specify exact allowed origins instead."
            )

        if reflects_evil and acac == "true":
            return self._create_finding(
                url, acao, acac, resp,
                "CORS reflects arbitrary origin with credentials",
                SeverityLevel.CRITICAL, 5, 4,
                "Server reflects Origin header in ACAO. Validate origin against allowlist before reflecting."
            )

        if is_wildcard:
            return self._create_finding(
                url, acao, acac, resp,
                "CORS allows all origins (wildcard) on API endpoint",
                SeverityLevel.MEDIUM, 3, 3,
                "Restrict Access-Control-Allow-Origin to specific trusted origins. "
                "Use allowlist: https://yourdomain.com, https://app.yourdomain.com"
            )

        if reflects_evil:
            return self._create_finding(
                url, acao, acac, resp,
                "CORS reflects arbitrary origin (origin reflection)",
                SeverityLevel.HIGH, 4, 4,
                "Server reflects Origin header without validation. Implement origin allowlist validation."
            )

        return None

    def _create_finding(
        self, url: str, acao: str, acac: str, resp,
        title: str, severity: SeverityLevel, impact: int, likelihood: int, remediation: str
    ) -> Finding:
        evidence = Evidence(
            url=url,
            snippet=f"ACAO: {acao}, ACAC: {acac}",
            request_headers={"Origin": self.EVIL_ORIGIN},
            response_headers=dict(resp.headers),
            response_status=resp.status_code,
        )
        return Finding(
            check=self.name,
            title=title,
            severity=severity,
            score=impact * likelihood,
            impact=impact,
            likelihood=likelihood,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.9,
            remediation=remediation,
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ],
        )