import re
import json

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient


class UnprotectedRoutesCheck(BaseCheck):
    name = "unprotected_routes"
    description = "Detects API routes that should require authentication but don't"
    wstg_id = ""
    attck_ids = []

    API_PATH_PATTERNS = [
        r"/api/",
        r"/graphql",
        r"/rest/",
        r"/v1/",
        r"/v2/",
        r"/auth/",
        r"/user",
        r"/account",
        r"/profile",
        r"/settings",
        r"/admin",
    ]

    SENSITIVE_RESPONSE_PATTERNS = [
        r"(?i)(user|account|profile|email|id|token|session)",
        r"(?i)(orders|purchases|billing|payment)",
        r"(?i)(admin|dashboard|analytics)",
    ]

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        api_endpoints = self._identify_api_endpoints(recon)

        for endpoint in api_endpoints:
            finding = await self._test_endpoint(endpoint, recon, http)
            if finding:
                findings.append(finding)

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    def _identify_api_endpoints(self, recon: ReconData) -> list[str]:
        endpoints = set()

        for page in recon.pages:
            for link in page.links:
                if any(re.search(p, link) for p in self.API_PATH_PATTERNS):
                    endpoints.add(link)

            for script in page.scripts:
                if any(re.search(p, script) for p in self.API_PATH_PATTERNS):
                    endpoints.add(script)

            for form in page.forms:
                action = form.get("action", "")
                if action and any(re.search(p, action) for p in self.API_PATH_PATTERNS):
                    endpoints.add(action)

        endpoints.update(recon.get_api_endpoints())

        filtered = []
        for ep in endpoints:
            if ep.startswith("/"):
                ep = f"{recon.base_url}{ep}"
            if ep.startswith(recon.base_url):
                filtered.append(ep)

        return list(set(filtered))[:30]

    async def _test_endpoint(self, url: str, recon: ReconData, http: HTTPClient) -> Finding | None:
        try:
            resp = await http.get(url, timeout=5.0)
        except Exception:
            return None

        if resp.status_code >= 400:
            return None

        content = resp.text
        content_type = resp.headers.get("content-type", "")

        if not self._looks_like_sensitive_data(content, content_type):
            return None

        if self._has_auth_indicators(resp):
            return None

        evidence = Evidence(
            url=url,
            snippet=content[:300],
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
        )

        impact = self._assess_impact(content)
        likelihood = 4

        return Finding(
            check=self.name,
            title=f"Unprotected API Endpoint: {url.replace(recon.base_url, '')}",
            severity=SeverityLevel.HIGH,
            score=impact * likelihood,
            impact=impact,
            likelihood=likelihood,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.7,
            remediation=(
                "Add authentication middleware to this route. "
                "In Next.js: export const middleware = authMiddleware; "
                "In Express: app.use('/api/', requireAuth); "
                "In Supabase: ensure RLS policies require auth."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_Authorization_Bypass",
            ],
        )

    def _looks_like_sensitive_data(self, content: str, content_type: str) -> bool:
        if "application/json" in content_type:
            return True
        if any(re.search(p, content) for p in self.SENSITIVE_RESPONSE_PATTERNS):
            return True
        return False

    def _has_auth_indicators(self, resp) -> bool:
        set_cookie = resp.headers.get("set-cookie", "")
        if "session" in set_cookie.lower() or "auth" in set_cookie.lower():
            return True
        www_auth = resp.headers.get("www-authenticate", "")
        if www_auth:
            return True
        
        # NEW: Authorization: Bearer <token> header
        auth_header = resp.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return True
        
        # NEW: JSON body with access_token/session/token
        if "application/json" in resp.headers.get("content-type", ""):
            try:
                import json
                body = resp.json() if hasattr(resp, 'json') else json.loads(resp.text)
                if isinstance(body, dict):
                    auth_keys = {"access_token", "session", "id_token", "refresh_token", "token"}
                    if any(k in body for k in auth_keys):
                        return True
            except Exception:
                pass
        
        return False

    def _assess_impact(self, content: str) -> int:
        content_lower = content.lower()
        if any(k in content_lower for k in ["password", "secret", "token", "key", "ssn", "credit"]):
            return 5
        if any(k in content_lower for k in ["email", "address", "phone", "order", "payment", "billing"]):
            return 4
        if any(k in content_lower for k in ["user", "profile", "account", "id", "name"]):
            return 3
        return 2