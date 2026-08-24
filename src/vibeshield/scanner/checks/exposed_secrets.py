from vibeshield.models.finding import Evidence, Finding
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.utils.http import HTTPClient
from vibeshield.utils.patterns import SECRET_PATTERNS


class ExposedSecretsCheck(BaseCheck):
    name = "exposed_secrets"
    description = "Detects API keys, tokens, and credentials exposed in client-side JavaScript"
    wstg_id = ""
    attck_ids = []

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        scripts = recon.get_all_scripts()
        all_html = recon.get_all_html()

        for js_url in scripts:
            try:
                resp = await http.get(js_url)
                if resp.status_code != 200:
                    continue
                content = resp.text
                findings.extend(self._scan_content(content, js_url, resp))
            except Exception:
                continue

        findings.extend(self._scan_content(all_html, recon.target_url, None))

        for env_path in ["/.env", "/.env.local", "/.env.production", "/.env.development"]:
            try:
                resp = await http.get(f"{recon.base_url}{env_path}")
                if resp.status_code == 200 and "=" in resp.text:
                    findings.append(self._create_env_finding(env_path, resp))
            except Exception:
                continue

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        from vibeshield.scanner.tagging import apply_tags_to_findings
        apply_tags_to_findings(findings, self.__class__.__name__)

        return findings

    def _scan_content(self, content: str, source_url: str, resp: HTTPClient | None) -> list[Finding]:
        findings = []
        for pattern_name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                matched = match.group(0)
                if len(matched) < 16:
                    continue

                snippet_start = max(0, match.start() - 50)
                snippet_end = min(len(content), match.end() + 50)
                snippet = content[snippet_start:snippet_end].replace("\n", " ")

                impact, likelihood = self._assess_severity(pattern_name, matched)
                severity, score = calculate_severity(impact, likelihood)

                evidence = Evidence(
                    url=source_url,
                    snippet=snippet,
                    matched_pattern=matched[:100],
                    response_status=resp.status_code if resp else None,
                    response_headers=dict(resp.headers) if resp else {},
                )

                findings.append(Finding(
                    check=self.name,
                    title=f"Exposed {pattern_name.replace('_', ' ').title()}",
                    severity=severity,
                    score=score,
                    impact=impact,
                    likelihood=likelihood,
                    wstg_id="",
                    attck_ids=[],
                    evidence=evidence,
                    confidence=0.9 if pattern_name != "generic_api_key" else 0.6,
                    remediation=self._get_remediation(pattern_name),
                    references=self._get_references(pattern_name),
                ))
        return findings

    def _assess_severity(self, pattern_name: str, matched: str) -> tuple[int, int]:
        high_value = ["aws_access_key", "aws_secret_key", "github_token", "slack_token",
                      "stripe_key", "sendgrid_key", "twilio_sid", "private_key"]
        if pattern_name in high_value:
            return 5, 4
        if pattern_name in ["supabase_key", "firebase_config"]:
            return 4, 4
        if pattern_name == "generic_api_key":
            return 3, 3
        if pattern_name == "env_assignment":
            return 3, 3
        return 2, 2

    def _get_remediation(self, pattern_name: str) -> str:
        remediation = {
            "aws_access_key": "Rotate key immediately in AWS IAM. Move to server-side environment variable.",
            "aws_secret_key": "Rotate key immediately in AWS IAM. Move to server-side environment variable.",
            "github_token": "Revoke token in GitHub Settings > Developer settings. Use GitHub Actions secrets.",
            "slack_token": "Revoke token in Slack API settings. Store in server-side env var.",
            "stripe_key": "Rotate key in Stripe Dashboard. Use server-side only for secret keys.",
            "sendgrid_key": "Rotate API key in SendGrid settings. Store server-side only.",
            "twilio_sid": "Rotate credentials in Twilio Console. Use server-side env vars.",
            "supabase_key": "This is likely the anon/public key (safe for client). Verify RLS is enabled on all tables.",
            "firebase_config": "Firebase config is public by design. Ensure Firestore/Realtime DB rules restrict access.",
            "generic_api_key": "Move key to server-side environment variable. Rotate if exposed.",
            "env_assignment": "Remove .env from client bundle. Use build-time substitution for public vars only.",
            "private_key": "Rotate key immediately. Never commit private keys to version control.",
        }
        return remediation.get(pattern_name, "Move secret to server-side environment variable and rotate.")

    def _get_references(self, pattern_name: str) -> list[str]:
        return [
            "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        ]

    def _create_env_finding(self, path: str, resp: HTTPClient) -> Finding:
        evidence = Evidence(
            url=f"{resp.url}",
            snippet=resp.text[:200],
            matched_pattern=".env file",
            response_status=resp.status_code,
            response_headers=dict(resp.headers),
        )
        severity, score = calculate_severity(5, 4)
        return Finding(
            check=self.name,
            title="Exposed .env File",
            severity=severity,
            score=score,
            impact=5,
            likelihood=4,
            wstg_id="",
            attck_ids=[],
            evidence=evidence,
            confidence=0.95,
            remediation="Remove .env from public directory. Use server-side env vars only. Rotate any exposed keys.",
            references=[
                "https://owasp.org/www-project-top-ten/2021/A07_2021-Identification_and_Authentication_Failures",
            ],
        )