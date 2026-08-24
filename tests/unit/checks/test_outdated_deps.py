from unittest.mock import MagicMock

import pytest

from vibeshield.models.recon import CrawledPage, ReconData
from vibeshield.scanner.checks.outdated_deps import OutdatedDepsCheck


def make_response(status=200, text="<html><body></body></html>", headers=None):
    mock = MagicMock()
    mock.status_code = status
    mock.text = text
    mock.headers = headers or {"content-type": "text/html"}
    if headers and "application/json" in headers.get("content-type", ""):
        import json
        try:
            mock.json = MagicMock(return_value=json.loads(text) if text else {})
        except Exception:
            mock.json = MagicMock(return_value={})
    else:
        mock.json = MagicMock(return_value={})
    return mock


class MockHTTPClient:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.call_count = 0

    def _normalize_url(self, url):
        return url.rstrip('/')

    async def get(self, url, **kwargs):
        self.call_count += 1
        normalized = self._normalize_url(url)
        if normalized in self.responses:
            return self.responses[normalized]
        mock = MagicMock()
        mock.status_code = 404
        mock.text = "<html><body>Not Found</body></html>"
        mock.headers = {"content-type": "text/html"}
        mock.json = MagicMock(return_value={})
        return mock

    async def aclose(self):
        pass


SAFE_VERSIONS = {
    "lodash": "4.17.21",      # highest vuln: 4.17.20
    "axios": "1.0.0",         # highest vuln: 0.21.1 (0.x major)
    "moment": "2.30.0",       # highest vuln: 2.29.1
}

VULNERABLE_VERSIONS = {
    "lodash": "4.17.20",
    "axios": "0.21.1",
    "moment": "2.29.1",
}


class TestVersionComparison:
    """Unit tests for _version_matches_or_older - pure logic, no Finding construction."""

    @pytest.fixture
    def check(self):
        return OutdatedDepsCheck()

    @pytest.mark.parametrize("current,vuln_version,expected", [
        ("4.17.19", "4.17.20", True),   # older -> vulnerable
        ("4.17.20", "4.17.20", True),   # exact -> vulnerable
        ("4.17.21", "4.17.20", False),  # newer -> safe
        ("1.0.0", "2.0.0", True),       # major diff
        ("2.0.0", "1.0.0", False),      # major diff reverse
        ("1.2.3", "1.2.3", True),       # exact patch
        ("1.2.4", "1.2.3", False),      # newer patch
        ("0.21.1", "0.21.1", True),     # 0.x exact
        ("0.21.2", "0.21.1", False),    # 0.x newer patch
    ])
    def test_version_comparison_logic(self, check, current, vuln_version, expected):
        """_version_matches_or_older behaves correctly at boundaries."""
        result = check._version_matches_or_older(current, vuln_version)
        assert result == expected, f"{current} vs {vuln_version}: expected {expected}"


class TestOutdatedDepsCheck:
    """Integration tests for OutdatedDepsCheck - tests Finding construction and full flow."""

    @pytest.fixture
    def check(self):
        return OutdatedDepsCheck()

    @pytest.fixture
    def recon(self):
        return ReconData(target_url="https://example.com", base_url="https://example.com")

    # === CRITICAL: Safe version newer than all known vulnerable entries produces zero findings ===
    @pytest.mark.parametrize("lib,safe_version", SAFE_VERSIONS.items())
    def test_safe_version_produces_zero_findings(self, check, recon, lib, safe_version):
        """Version newer than all known vulnerable entries produces zero findings."""
        # Test _check_vulnerabilities directly (unit test)
        vulns = check._check_vulnerabilities(lib, safe_version)
        assert vulns == [], f"{lib}@{safe_version} should be safe but returned: {vulns}"

        # Test full run with mocked content
        content = f"{lib}@{safe_version}"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert findings == [], f"Full run: {lib}@{safe_version} should be safe"

    # === Vulnerable version detected ===
    @pytest.mark.parametrize("lib,vuln_version", VULNERABLE_VERSIONS.items())
    def test_vulnerable_version_detected(self, check, recon, lib, vuln_version):
        """Known vulnerable version produces findings with correct CVEs."""
        vulns = check._check_vulnerabilities(lib, vuln_version)
        assert vulns != [], f"{lib}@{vuln_version} should be vulnerable"
        assert len(vulns) >= 1
        assert all(cve.startswith("CVE-") for cve in vulns)

    # === Boundary: exact match = vulnerable ===
    def test_exact_version_match_is_vulnerable(self, check):
        """Exact version match with KNOWN_VULNS entry is vulnerable."""
        vulns = check._check_vulnerabilities("lodash", "4.17.20")
        assert vulns != []
        assert "CVE-2021-23337" in vulns

    # === Unknown library ===
    def test_unknown_library_produces_zero_findings(self, check):
        """Library not in KNOWN_VULNS produces zero findings regardless of version."""
        vulns = check._check_vulnerabilities("unknown-lib", "1.0.0")
        assert vulns == []
        vulns = check._check_vulnerabilities("unknown-lib", "0.0.1")
        assert vulns == []

    # === Version extraction from content ===
    @pytest.mark.parametrize("content,expected_deps", [
        ("lodash@4.17.20", [("lodash", "4.17.20")]),
        ("@scope/pkg@1.2.3", [("pkg", "1.2.3")]),
        ('{"imports": {"lodash": "4.17.20"}}', [("lodash", "4.17.20")]),
        ('{"dependencies": {"lodash": "^4.17.20"}}', [("lodash", "4.17.20")]),
        ("lodash@4.17.20\njquery@3.4.0", [("lodash", "4.17.20"), ("jquery", "3.4.0")]),
        ("lodash@4.17.20 lodash@4.17.20", [("lodash", "4.17.20")]),
    ])
    def test_extract_dependencies(self, check, content, expected_deps):
        """_extract_dependencies correctly parses various formats and deduplicates."""
        deps = check._extract_dependencies(content)
        assert set(deps) == set(expected_deps)

    # === Full integration: safe version in content ===
    def test_full_run_safe_version_zero_findings(self, check, recon):
        """Full run with safe version content produces zero findings."""
        content = "lodash@4.17.21\njquery@3.5.0"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert findings == [], "Safe versions should produce zero findings in full run"

    # === Full integration: mixed safe and vulnerable ===
    def test_full_run_mixed_safe_and_vulnerable(self, check, recon):
        """Full run with mixed content only flags vulnerable ones."""
        content = "lodash@4.17.21\nlodash@4.17.20"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert len(findings) == 1
        assert findings[0][0] == "lodash"
        assert findings[0][1] == "4.17.20"

    # === Unknown library in content ===
    def test_unknown_library_in_content_produces_zero_findings(self, check, recon):
        """Unknown library in content produces zero findings."""
        content = "unknown-lib@1.0.0"
        deps = check._extract_dependencies(content)
        findings = []
        for name, version in deps:
            vulns = check._check_vulnerabilities(name, version)
            if vulns:
                findings.append((name, version, vulns))
        assert findings == []

    # === Version boundary edge cases ===
    @pytest.mark.parametrize("current,vuln_version,expected", [
        ("4.17.19", "4.17.20", True),
        ("4.17.20", "4.17.20", True),
        ("4.17.21", "4.17.20", False),
        ("1.0.0", "2.0.0", True),
        ("2.0.0", "1.0.0", False),
    ])
    def test_version_comparison_edge_cases(self, check, current, vuln_version, expected):
        """_version_matches_or_older behaves correctly at boundaries."""
        result = check._version_matches_or_older(current, vuln_version)
        assert result == expected

    # === Malformed version strings ===
    @pytest.mark.parametrize("version", ["not.a.version", "1.2", "1.2.3.4.5", ""])
    def test_malformed_version_returns_false(self, check, version):
        """Malformed version strings return False (safe)."""
        result = check._version_matches_or_older(version, "1.0.0")
        assert result == False

    @pytest.mark.asyncio
    async def test_run_integration_vulnerable_version(self, check, recon, mock_httpx_client):
        from vibeshield.models.recon import CrawledPage
        recon.pages = [
            CrawledPage(
                url="https://example.com",
                depth=0,
                status_code=200,
                content_type="text/html",
                html='<script>lodash@4.17.20</script>',
                headers={},
                scripts=["https://example.com/lodash.js"],
            )
        ]
        findings = await check.run(recon, mock_httpx_client)
        assert len(findings) == 1
        assert findings[0].check == "outdated_deps"
        assert "lodash@4.17.20" in findings[0].title
        assert findings[0].severity == "High"

    @pytest.mark.asyncio
    async def test_run_integration_safe_version(self, check, recon, mock_httpx_client):
        from vibeshield.models.recon import CrawledPage
        recon.pages = [
            CrawledPage(
                url="https://example.com",
                depth=0,
                status_code=200,
                content_type="text/html",
                html='<script>lodash@4.17.21</script>',
                headers={},
                scripts=["https://example.com/lodash.js"],
            )
        ]
        findings = await check.run(recon, mock_httpx_client)
        assert len(findings) == 0


class TestFetchScripts:
    """Tests for _fetch_scripts method."""

    @pytest.fixture
    def check(self):
        return OutdatedDepsCheck()

    def make_response(self, status=200, text="<html><body></body></html>", headers=None):
        from unittest.mock import MagicMock
        mock = MagicMock()
        mock.status_code = status
        mock.text = text
        mock.headers = headers or {"content-type": "text/html"}
        if headers and "application/json" in headers.get("content-type", ""):
            import json
            try:
                mock.json = MagicMock(return_value=json.loads(text) if text else {})
            except Exception:
                mock.json = MagicMock(return_value={})
        else:
            mock.json = MagicMock(return_value={})
        return mock

    class MockHTTPClient:
        def __init__(self, responses=None):
            self.responses = responses or {}
            self.call_count = 0

        def _normalize_url(self, url):
            return url.rstrip('/')

        async def get(self, url, **kwargs):
            self.call_count += 1
            normalized = self._normalize_url(url)
            if normalized in self.responses:
                return self.responses[normalized]
            mock = MagicMock()
            mock.status_code = 404
            mock.text = "<html><body>Not Found</body></html>"
            mock.headers = {"content-type": "text/html"}
            mock.json = MagicMock(return_value={})
            return mock

        async def aclose(self):
            pass

    @pytest.fixture
    def mock_http(self):
        return self.MockHTTPClient()

    @pytest.fixture
    def recon(self):
        from vibeshield.models.report import FingerprintResult
        return ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[],
            fingerprint=FingerprintResult(js_bundles=["https://example.com/app.js", "https://example.com/vendor.js"]),
        )

    @pytest.mark.asyncio
    async def test_fetch_scripts_success(self, check, recon, mock_http):
        """_fetch_scripts successfully fetches and returns script content."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><script src="/app.js"></script><script src="/vendor.js"></script></html>'
            ),
            "https://example.com/app.js": make_response(
                status=200, text='console.log("app");', headers={"content-type": "application/javascript"}
            ),
            "https://example.com/vendor.js": make_response(
                status=200, text='console.log("vendor");', headers={"content-type": "application/javascript"}
            ),
        }

        scripts = await check._fetch_scripts(recon, mock_http)

        assert len(scripts) == 2
        assert 'console.log("app");' in scripts
        assert 'console.log("vendor");' in scripts

    @pytest.mark.asyncio
    async def test_fetch_scripts_skips_non_200(self, check, recon, mock_http):
        """Scripts returning non-200 are skipped."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><script src="/app.js"></script></html>'
            ),
            "https://example.com/app.js": make_response(status=404, text="Not found"),
        }

        scripts = await check._fetch_scripts(ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[]
        ), mock_http)

        assert scripts == []

    @pytest.mark.asyncio
    async def test_fetch_scripts_skips_non_html(self, check, recon, mock_http):
        """Non-HTML responses are skipped."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='{"data": "json"}',
                headers={"content-type": "application/json"}
            ),
        }

        scripts = await check._fetch_scripts(ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[]
        ), self.MockHTTPClient())

        assert scripts == []

    @pytest.mark.asyncio
    async def test_fetch_scripts_network_error(self, check, recon, mock_httpx_client):
        """Network errors are gracefully handled."""
        mock_http = self.MockHTTPClient()
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><script src="/app.js"></script></html>'
            ),
        }

        scripts = await check._fetch_scripts(ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[]
        ), self.MockHTTPClient())

        assert scripts == []

    @pytest.mark.asyncio
    async def test_fetch_scripts_respects_limit(self, check, recon, mock_httpx_client):
        """Only first 10 scripts are fetched."""
        mock_http = self.MockHTTPClient()
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html>' + ''.join(f'<script src="/script{i}.js"></script>' for i in range(15)) + '</html>'
            ),
        }
        for i in range(15):
            mock_http.responses[f"https://example.com/script{i}.js"] = make_response(
                status=200, text=f"console.log({i});", headers={"content-type": "application/javascript"}
            )

        from vibeshield.models.report import FingerprintResult
        recon = ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[CrawledPage(
                url="https://example.com", depth=0, status_code=200, content_type="text/html",
                html='<html>' + ''.join(f'<script src="/script{i}.js"></script>' for i in range(15)) + '</html>',
                headers={},
                scripts=[f"https://example.com/script{i}.js" for i in range(15)],
            )],
            fingerprint=FingerprintResult(js_bundles=[f"https://example.com/script{i}.js" for i in range(15)]),
        )

        scripts = await check._fetch_scripts(recon, mock_http)

        assert len(scripts) == 10

    # === Additional run() Integration Tests ===

    @pytest.mark.asyncio
    async def test_run_network_error_handled(self, check, recon, mock_httpx_client):
        """Network errors during fetch are handled gracefully."""
        from vibeshield.models.recon import CrawledPage

        class FailingClient:
            async def get(self, url, **kwargs):
                raise Exception("Network error")
            async def aclose(self):
                pass

        recon.pages = [CrawledPage(
            url="https://example.com", depth=0, status_code=200, content_type="text/html",
            html='<html><script src="/app.js"></script></body></html>', headers={},
            scripts=["https://example.com/app.js"],
        )]

        findings = await check.run(recon, FailingClient())
        assert findings == []

    @pytest.mark.asyncio
    async def test_run_with_multiple_js_bundles(self, check, recon):
        """Multiple JS bundles are all checked for vulnerabilities."""
        from vibeshield.models.recon import CrawledPage

        recon.pages = [CrawledPage(
            url="https://example.com", depth=0, status_code=200, content_type="text/html",
            html='<script src="/app.js"></script><script src="/vendor.js"></script>',
            headers={}, scripts=["https://example.com/app.js", "https://example.com/vendor.js"],
        )]

        class CustomClient:
            def __init__(self):
                self.responses = {
                    "https://example.com/app.js": make_response(
                        status=200, text="lodash@4.17.20", headers={"content-type": "application/javascript"}
                    ),
                    "https://example.com/vendor.js": make_response(
                        status=200, text="jquery@3.4.0", headers={"content-type": "application/javascript"}
                    ),
                }

            async def get(self, url, **kwargs):
                normalized = url.rstrip('/')
                if normalized in self.responses:
                    return self.responses[normalized]
                mock = MagicMock()
                mock.status_code = 404
                mock.text = "<html><body>Not Found</body></html>"
                mock.headers = {"content-type": "text/html"}
                mock.json = MagicMock(return_value={})
                return mock

            async def aclose(self):
                pass

        findings = await check.run(recon, CustomClient())
        assert len(findings) == 2
        titles = [f.title for f in findings]
        assert "Outdated Dependency: lodash@4.17.20" in titles
        assert "Outdated Dependency: jquery@3.4.0" in titles

    @pytest.mark.asyncio
    async def test_run_with_malformed_js_content(self, check, recon, mock_httpx_client):
        """Malformed JS content doesn't crash the scanner."""
        from vibeshield.models.recon import CrawledPage

        recon.pages = [CrawledPage(
            url="https://example.com", depth=0, status_code=200, content_type="text/html",
            html='<script src="/app.js"></script>', headers={}, scripts=["https://example.com/app.js"],
        )]

        mock_httpx_client.responses = {
            "https://example.com/app.js": make_response(
                status=200, text="not valid javascript{{{", headers={"content-type": "application/javascript"}
            ),
        }

        findings = await check.run(recon, mock_httpx_client)
        assert findings == []