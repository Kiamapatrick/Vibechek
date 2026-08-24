import logging
import re

from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.base import BaseCheck
from vibeshield.scanner.scoring import calculate_severity
from vibeshield.scanner.tagging import apply_tags_to_findings
from vibeshield.utils.http import HTTPClient

log = logging.getLogger(__name__)


class SupabaseFirebaseCheck(BaseCheck):
    name = "supabase_firebase"
    description = "Detects Supabase/Firebase misconfigurations allowing unauthorized data access"

    # Class attribute for hasattr() check in engine - enables write tests when set via CLI flag
    allow_write_tests: bool = False

    def __init__(self):
        super().__init__()
        self.supabase_key_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
        self.firebase_config_pattern = re.compile(
            r"firebaseConfig\s*=\s*\{[^}]*projectId\s*:\s*[\"']([^\"']+)[\"']", re.DOTALL
        )
        self.supabase_url_pattern = re.compile(r"https://([a-z0-9-]+)\.supabase\.co")

    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        all_content = recon.get_all_html() + "\n".join(
            await self._fetch_scripts(recon, http)
        )

        supabase_findings = await self._check_supabase(all_content, recon, http)
        findings.extend(supabase_findings)

        firebase_findings = await self._check_firebase(all_content, recon, http)
        findings.extend(firebase_findings)

        for f in findings:
            f.severity, f.score = calculate_severity(f.impact, f.likelihood)

        apply_tags_to_findings(findings, self.__class__.__name__)
        return findings

    async def _fetch_scripts(self, recon: ReconData, http: HTTPClient) -> list[str]:
        scripts = []
        for js_url in recon.get_js_bundles():
            try:
                resp = await http.get(js_url)
                if resp.status_code == 200:
                    scripts.append(resp.text)
            except Exception:
                log.warning("Failed to fetch script", exc_info=True)
                continue
        return scripts

    async def _check_supabase(self, content: str, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        anon_keys = self.supabase_key_pattern.findall(content)
        supabase_urls = self.supabase_url_pattern.findall(content)

        for key in anon_keys:
            if self._is_supabase_anon_key(key):
                for url in supabase_urls or [recon.base_url]:
                    base = f"https://{url}.supabase.co" if not url.startswith("http") else url
                    finding = await self._test_supabase_rls(base, key, http)
                    if finding:
                        findings.append(finding)
        return findings

    def _is_supabase_anon_key(self, key: str) -> bool:
        try:
            import base64
            import json
            parts = key.split(".")
            if len(parts) != 3:
                return False
            payload = parts[1]
            payload += "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload).decode()
            data = json.loads(decoded)
            role = data.get("role", "")
            return role in ("anon", "anonymous")
        except Exception:
            log.warning("Failed to parse JWT", exc_info=True)
            return False

    async def _test_supabase_rls(self, base_url: str, anon_key: str, http: HTTPClient) -> Finding | None:
        test_tables = ["users", "profiles", "posts", "comments", "orders", "products"]
        headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }

        for table in test_tables:
            # PRIMARY: GET first (read test) — always runs
            try:
                resp = await http.get(
                    f"{base_url}/rest/v1/{table}",
                    headers=headers,
                    timeout=5.0,
                )
                if resp.status_code == 200 and resp.text not in ("null", ""):
                    evidence = Evidence(
                        url=f"{base_url}/rest/v1/{table}",
                        snippet=f"GET succeeded - RLS may not be blocking reads on '{table}': {resp.text[:200]}",
                        matched_pattern=anon_key[:20] + "...",
                        request_headers=headers,
                        response_headers=dict(resp.headers),
                        response_status=resp.status_code,
                    )
                    return Finding(
                        check=self.name,
                        title=f"Supabase RLS Read Bypass on '{table}' Table",
                        severity=SeverityLevel.HIGH,
                        score=16,
                        impact=4,
                        likelihood=4,
                        wstg_id="",
                        attck_ids=[],
                        evidence=evidence,
                        confidence=0.8,
                        remediation=(
                            f"Enable Row Level Security on '{table}' table. "
                            f"Add SELECT policy: `CREATE POLICY ... FOR SELECT USING (auth.role() = 'authenticated');`"
                        ),
                        references=[
                            "https://supabase.com/docs/guides/auth/row-level-security",
                        ],
                    )
            except Exception:
                log.warning("Supabase GET request failed", exc_info=True)

            # CONDITIONAL: POST only if write tests enabled
            if self.allow_write_tests:
                try:
                    resp = await http.post(
                        f"{base_url}/rest/v1/{table}",
                        headers=headers,
                        json={},
                        timeout=5.0,
                    )
                    if resp.status_code == 201:
                        evidence = Evidence(
                            url=f"{base_url}/rest/v1/{table}",
                            snippet=f"POST succeeded - RLS may not be blocking inserts on '{table}'",
                            matched_pattern=anon_key[:20] + "...",
                            request_headers=headers,
                            response_headers=dict(resp.headers),
                            response_status=resp.status_code,
                        )
                        return Finding(
                            check=self.name,
                            title=f"Supabase RLS Bypass on '{table}' Table",
                            severity=SeverityLevel.CRITICAL,
                            score=20,
                            impact=5,
                            likelihood=4,
                            wstg_id="",
                            attck_ids=[],
                            evidence=evidence,
                            confidence=0.85,
                            remediation=(
                                f"Enable Row Level Security on '{table}' table in Supabase Dashboard. "
                                f"Create policies: `CREATE POLICY ... USING (auth.role() = 'authenticated');`"
                            ),
                            references=[
                                "https://supabase.com/docs/guides/auth/row-level-security",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_Authorization_Bypass",
                            ],
                        )
                except Exception:
                    log.warning("Supabase POST request failed", exc_info=True)
        return None

    async def _check_firebase(self, content: str, recon: ReconData, http: HTTPClient) -> list[Finding]:
        findings = []
        firebase_matches = self.firebase_config_pattern.findall(content)

        for project_id in firebase_matches:
            finding = await self._test_firebase_access(project_id, http)
            if finding:
                findings.append(finding)
        return findings

    async def _test_firebase_access(self, project_id: str, http: HTTPClient) -> Finding | None:
        rt_db_url = f"https://{project_id}-default-rtdb.firebaseio.com/.json"
        try:
            resp = await http.get(rt_db_url, timeout=5.0)
            if resp.status_code == 200 and resp.text not in ("null", ""):
                evidence = Evidence(
                    url=rt_db_url,
                    snippet=f"Realtime DB accessible: {resp.text[:200]}",
                    matched_pattern=project_id,
                    response_headers=dict(resp.headers),
                    response_status=resp.status_code,
                )
                return Finding(
                    check=self.name,
                    title="Firebase Realtime Database Publicly Readable",
                    severity=SeverityLevel.CRITICAL,
                    score=20,
                    impact=5,
                    likelihood=4,
                    wstg_id="",
                    attck_ids=[],
                    evidence=evidence,
                    confidence=0.9,
                    remediation=(
                        "Set Realtime Database rules to require auth: "
                        '{"rules": {".read": "auth != null", ".write": "auth != null"}}'
                    ),
                    references=[
                        "https://firebase.google.com/docs/database/security",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_Authorization_Bypass",
                    ],
                )
        except Exception:
                log.warning("Firebase Realtime DB request failed", exc_info=True)

        firestore_url = (
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        )
        try:
            resp = await http.get(firestore_url, timeout=5.0)
            if resp.status_code == 200:
                evidence = Evidence(
                    url=firestore_url,
                    snippet="Firestore API accessible without auth",
                    matched_pattern=project_id,
                    response_headers=dict(resp.headers),
                    response_status=resp.status_code,
                )
                return Finding(
                    check=self.name,
                    title="Firestore API Accessible Without Authentication",
                    severity=SeverityLevel.HIGH,
                    score=15,
                    impact=4,
                    likelihood=3,
                    wstg_id="",
                    attck_ids=[],
                    evidence=evidence,
                    confidence=0.75,
                    remediation="Set Firestore security rules to require authentication for all reads/writes.",
                    references=[
                        "https://firebase.google.com/docs/firestore/security/get-started",
                    ],
                )
        except Exception:
            log.warning("Firestore API request failed", exc_info=True)

        return None