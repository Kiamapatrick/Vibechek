from typing import ClassVar

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient


class SecurityHeadersCheck(BaseCheck):
    name = "security_headers"
    description = "Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)"

    REQUIRED_HEADERS: ClassVar[dict[str, dict[str, str | int]]] = {
        "content-security-policy": {
            "severity": "Medium",
            "impact": 3,
            "likelihood": 3,
            "description": "Content Security Policy missing - allows XSS and data injection",
        },
        "strict-transport-security": {
            "severity": "Medium",
            "impact": 3,
            "likelihood": 3,
            "description": "HSTS missing - allows SSL stripping attacks",
        },
        "x-frame-options": {
            "severity": "Low",
            "impact": 2,
            "likelihood": 3,
            "description": "X-Frame-Options missing - allows clickjacking",
        },
        "x-content-type-options": {
            "severity": "Low",
            "impact": 2,
            "likelihood": 2,
            "description": "X-Content-Type-Options missing - allows MIME sniffing",
        },
        "referrer-policy": {
            "severity": "Info",
            "impact": 1,
            "likelihood": 2,
            "description": "Referrer-Policy missing - may leak referrer info",
        },
        "permissions-policy": {
            "severity": "Info",
            "impact": 1,
            "likelihood": 2,
            "description": "Permissions-Policy missing - no feature policy control",
        },
    }

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []

        for page in recon.pages[:5]:
            headers = {k.lower(): v for k, v in page.headers.items()}
            findings.extend(self._check_headers(page.url, headers, page))

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    def _check_headers(self, url: str, headers: dict, page) -> list[Finding]:
        findings = []
        csp_header = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")

        for header_name, config in self.REQUIRED_HEADERS.items():
            if header_name == "content-security-policy":
                if not csp_header:
                    findings.append(self._create_finding(url, header_name, config, page))
                elif not self._csp_has_frame_ancestors(csp_header):
                    findings.append(self._create_csp_frame_ancestors_finding(url, csp_header, page))
            elif header_name == "x-frame-options":
                if not headers.get("x-frame-options") and not self._csp_has_frame_ancestors(csp_header):
                    findings.append(self._create_finding(url, header_name, config, page))
            elif header_name not in headers:
                findings.append(self._create_finding(url, header_name, config, page))

        server_header = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")
        if server_header or x_powered_by:
            findings.append(self._create_info_disclosure_finding(url, server_header, x_powered_by, page))

        return findings

    def _csp_has_frame_ancestors(self, csp: str | None) -> bool:
        if not csp:
            return False
        return "frame-ancestors" in csp.lower()

    def _create_finding(self, url: str, header_name: str, config: dict, page) -> Finding:
        evidence = Evidence(
            url=url,
            snippet=f"Missing header: {header_name}",
            response_status=page.status_code,
            response_headers=page.headers,
        )
        return Finding(
            check=self.name,
            title=f"Missing Security Header: {header_name.upper()}",
            severity=SeverityLevel.MEDIUM,
            score=config["impact"] * config["likelihood"],
            impact=config["impact"],
            likelihood=config["likelihood"],
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.95,
            remediation=self._get_remediation(header_name),
            references=self._get_references(header_name),
        )

    def _create_csp_frame_ancestors_finding(self, url: str, csp: str, page) -> Finding:
        evidence = Evidence(
            url=url,
            snippet=f"CSP missing frame-ancestors: {csp[:200]}",
            response_status=page.status_code,
            response_headers=page.headers,
        )
        return Finding(
            check=self.name,
            title="CSP Missing frame-ancestors Directive",
            severity=SeverityLevel.LOW,
            score=2 * 3,
            impact=2,
            likelihood=3,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.8,
            remediation="Add 'frame-ancestors 'self'' or 'frame-ancestors 'none'' to CSP header.",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",
            ],
        )

    def _create_info_disclosure_finding(self, url: str, server: str, x_powered_by: str, page) -> Finding:
        details = []
        if server:
            details.append(f"Server: {server}")
        if x_powered_by:
            details.append(f"X-Powered-By: {x_powered_by}")

        evidence = Evidence(
            url=url,
            snippet="; ".join(details),
            response_status=page.status_code,
            response_headers=page.headers,
        )
        return Finding(
            check=self.name,
            title="Server Version Disclosure",
            severity=SeverityLevel.INFO,
            score=1 * 2,
            impact=1,
            likelihood=2,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.9,
            remediation="Remove or obfuscate Server and X-Powered-By headers. In Nginx: server_tokens off; In Express: app.disable('x-powered-by')",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
            ],
        )

    def _get_remediation(self, header_name: str) -> str:
        remediation = {
            "content-security-policy": (
                "Add CSP header. Start with: "
                "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
            ),
            "strict-transport-security": (
                "Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
            "x-frame-options": "Add X-Frame-Options: DENY (or SAMEORIGIN if you need framing)",
            "x-content-type-options": "Add X-Content-Type-Options: nosniff",
            "referrer-policy": "Add Referrer-Policy: strict-origin-when-cross-origin",
            "permissions-policy": "Add Permissions-Policy: geolocation=(), microphone=(), camera=()",
        }
        return remediation.get(header_name, f"Add {header_name} header")

    def _get_references(self, header_name: str) -> list[str]:
        base = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_Client_Side_Cross_Site_Scripting"
        refs = {
            "content-security-policy": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                base,
            ],
            "strict-transport-security": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
            "x-frame-options": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            ],
        }
        return refs.get(header_name, [base])