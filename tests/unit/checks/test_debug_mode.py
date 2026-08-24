from unittest.mock import MagicMock

import pytest

from vibeshield.models.finding import SeverityLevel
from vibeshield.models.recon import CrawledPage, ReconData
from vibeshield.scanner.checks.debug_mode import DebugModeCheck


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
        return mock


def make_response(status=200, text="<html><body></body></html>", headers=None):
    mock = MagicMock()
    mock.status_code = status
    mock.text = text
    mock.headers = headers or {"content-type": "text/html"}
    return mock


class TestDebugModeCheck:
    @pytest.fixture
    def check(self):
        return DebugModeCheck()

    @pytest.fixture
    def recon(self):
        return ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[
                CrawledPage(
                    url="https://example.com",
                    depth=0,
                    status_code=200,
                    content_type="text/html",
                    html="<html><body>Home</body></html>",
                    headers={"x-powered-by": "Express"},
                    scripts=["https://example.com/app.js"],
                ),
            ],
        )

    @pytest.fixture
    def mock_http(self):
        return MockHTTPClient()

    # === Verbose Error Tests ===

    @pytest.mark.asyncio
    async def test_verbose_stack_trace_detected(self, check, recon, mock_http):
        """Stack trace in 404 response triggers finding."""
        check.allow_write_tests = False  # not used but set for consistency

        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text='<html><body><pre>Traceback (most recent call last):\n  File "app.py", line 10, in <module>\n    raise ValueError()</pre></body></html>'
            ),
        }

        findings = await check._check_verbose_errors(recon, mock_http)
        assert len(findings) >= 1
        assert any("Stack trace" in f.title for f in findings)
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert findings[0].confidence == 0.85

    @pytest.mark.asyncio
    async def test_verbose_source_path_disclosure(self, check, recon, mock_http):
        """Source code path in error response triggers finding."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=500,
                text='<html><body>File "/var/www/app/views.py", line 42, in index</body></html>'
            ),
        }

        findings = await check._check_verbose_errors(recon, mock_http)
        assert len(findings) >= 1
        assert any("Source code path" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_verbose_debug_flag_detected(self, check, recon, mock_http):
        """Debug flag in response triggers finding."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text='<html><body>DEBUG = True\nNEXT_DEBUG=1</body></html>'
            ),
        }

        findings = await check._check_verbose_errors(recon, mock_http)
        assert len(findings) >= 1
        assert any("Debug flag" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_verbose_webpack_internals_detected(self, check, recon, mock_http):
        """Webpack internals in response triggers finding."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text='<html><body>webpack://webpack/./src/main.js</body></html>'
            )
        }

        findings = await check._check_verbose_errors(recon, mock_http)
        assert len(findings) >= 1
        assert any("Source map" in f.title or "bundle internals" in f.title for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_on_clean_error_page(self, check, recon, mock_http):
        """Clean 404 without debug info produces no finding."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text="<html><body>Page not found</body></html>"
            ),
        }

        findings = await check._check_verbose_errors(recon, mock_http)
        assert findings == []

    @pytest.mark.asyncio
    async def test_verbose_errors_short_circuits_on_first_match(self, check, recon, mock_http):
        """Only one finding per URL, stops at first pattern match."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text='Stack trace\nFile "app.py", line 10\nException occurred'
            ),
        }

        findings = await check._check_verbose_errors(recon, mock_http)
        # Should only get one finding (first pattern that matches)
        assert len(findings) == 1

    # === Debug Endpoint Tests ===

    @pytest.mark.asyncio
    async def test_debug_endpoint_exposed(self, check, recon, mock_http):
        """Accessible debug endpoint triggers finding."""
        mock_http.responses = {
            "https://example.com/debug": make_response(
                status=200,
                text="Debug panel: enabled"
            ),
        }

        findings = await check._check_debug_endpoints(recon, mock_http)
        assert len(findings) >= 1
        assert any("Exposed Debug Endpoint" in f.title for f in findings)
        assert findings[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_multiple_debug_endpoints(self, check, recon, mock_http):
        """Multiple debug endpoints each trigger findings."""
        mock_http.responses = {
            "https://example.com/debug": make_response(status=200, text="Debug"),
            "https://example.com/__debug__": make_response(status=200, text="Debug"),
            "https://example.com/_debug": make_response(status=404, text="Not found"),
        }

        findings = await check._check_debug_endpoints(recon, mock_http)
        assert len(findings) == 2  # only 200 responses

    @pytest.mark.asyncio
    async def test_debug_endpoint_not_exposed(self, check, recon, mock_http):
        """Non-existent debug endpoint (404) produces no finding."""
        mock_http.responses = {
            "https://example.com/debug": make_response(status=404, text="Not found"),
        }

        findings = await check._check_debug_endpoints(recon, mock_http)
        assert len(findings) == 0

    # === Source Map Tests ===

    @pytest.mark.asyncio
    async def test_source_map_detected(self, check, recon):
        """JS files with .map suffix trigger source map finding."""
        recon.pages[0].scripts = [
            "https://example.com/app.js",
            "https://example.com/vendor.js",
        ]

        findings = check._check_source_maps(recon)
        assert len(findings) == 2
        assert all("Source Map" in f.title for f in findings)
        assert all(f.severity == SeverityLevel.LOW for f in findings)

    @pytest.mark.asyncio
    async def test_source_map_deduplication(self, check, recon):
        """Duplicate source maps are deduplicated."""
        recon.pages[0].scripts = [
            "https://example.com/app.js",
            "https://example.com/app.js",  # duplicate
        ]

        findings = check._check_source_maps(recon)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_non_js_scripts_ignored(self, check, recon):
        """Non-JS scripts don't trigger source map findings."""
        recon.pages[0].scripts = [
            "https://example.com/style.css",
            "https://example.com/image.png",
        ]

        findings = check._check_source_maps(recon)
        assert findings == []

    # === Debug Header Tests ===

    def test_debug_token_header_detected(self, check, recon):
        """X-Debug-Token header triggers finding."""
        recon.pages[0].headers = {"x-debug-token": "abc123"}

        findings = check._check_debug_headers(recon)
        assert len(findings) == 1
        assert findings[0].title == "Debug Headers Present"
        assert findings[0].severity == SeverityLevel.INFO
        assert "X-Debug-Token" in findings[0].evidence.snippet

    def test_drupal_cache_header_detected(self, check, recon):
        """X-Drupal-Cache header triggers finding."""
        recon.pages[0].headers = {"x-drupal-cache": "HIT"}

        findings = check._check_debug_headers(recon)
        assert len(findings) == 1
        assert "X-Drupal-Cache" in findings[0].evidence.snippet

    def test_debug_powered_by_header_detected(self, check, recon):
        """X-Powered-By with 'debug' triggers finding."""
        recon.pages[0].headers = {"x-powered-by": "Express Debug"}

        findings = check._check_debug_headers(recon)
        assert len(findings) == 1
        assert "X-Powered-By" in findings[0].evidence.snippet

    def test_no_debug_headers_no_finding(self, check, recon):
        """Normal headers produce no findings."""
        recon.pages[0].headers = {"server": "nginx", "content-type": "text/html"}

        findings = check._check_debug_headers(recon)
        assert findings == []

    # === Full Run Integration Tests ===

    @pytest.mark.asyncio
    async def test_full_run_verbose_errors_only(self, check, recon, mock_http):
        """Full run with verbose errors produces correct findings."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text='<html><body>Traceback (most recent call last):\n  File "app.py", line 10</body></html>'
            ),
        }

        findings = await check.run(recon, mock_http)
        verbose_findings = [f for f in findings if "Verbose Error" in f.title]
        assert len(verbose_findings) == 1

    @pytest.mark.asyncio
    async def test_full_run_debug_endpoint_only(self, check, recon, mock_http):
        """Full run with debug endpoint produces correct findings."""
        mock_http.responses = {
            "https://example.com/debug": make_response(status=200, text="Debug panel"),
        }

        findings = await check.run(recon, mock_http)
        debug_findings = [f for f in findings if "Exposed Debug Endpoint" in f.title]
        assert len(debug_findings) == 1

    @pytest.mark.asyncio
    async def test_full_run_source_maps_only(self, check, recon):
        """Full run with source maps produces correct findings."""
        recon.pages[0].scripts = ["https://example.com/app.js"]

        findings = await check.run(recon, None)
        source_map_findings = [f for f in findings if "Source Map" in f.title]
        assert len(source_map_findings) == 1

    @pytest.mark.asyncio
    async def test_full_run_debug_headers_only(self, check, recon):
        """Full run with debug headers produces correct findings."""
        recon.pages[0].headers = {"x-debug-token": "abc123"}

        findings = await check.run(recon, None)
        header_findings = [f for f in findings if "Debug Headers" in f.title]
        assert len(header_findings) == 1

    # === Confidence and Scoring Tests ===

    def test_confidence_values(self, check, recon):
        """All findings have confidence between 0 and 1."""
        # Test via direct method calls
        findings = check._check_source_maps(recon)
        for f in findings:
            assert 0 <= f.confidence <= 1

    @pytest.mark.asyncio
    async def test_severity_levels_correct(self, check, recon, mock_http):
        """Each finding type has correct severity."""
        mock_http.responses = {
            "https://example.com/nonexistent-page-12345": make_response(
                status=404,
                text='Stack trace\n  File "app.py", line 10'
            ),
            "https://example.com/debug": make_response(status=200, text="Debug"),
        }
        recon.pages[0].headers = {"x-debug-token": "abc"}
        recon.pages[0].scripts = ["https://example.com/app.js"]

        findings = await check.run(recon, mock_http)
        severities = {f.title: f.severity for f in findings}

        # Check verbose error (stack trace) -> MEDIUM
        verbose_error_severities = [s for t, s in severities.items() if "Verbose Error Page" in t]
        assert SeverityLevel.MEDIUM in verbose_error_severities

        # Check debug endpoint -> HIGH
        debug_endpoint_severities = [s for t, s in severities.items() if "Exposed Debug Endpoint" in t]
        assert SeverityLevel.HIGH in debug_endpoint_severities

        # Check source map -> LOW
        source_map_severities = [s for t, s in severities.items() if "Source Map" in t]
        assert SeverityLevel.LOW in source_map_severities

        # Check debug headers -> INFO
        header_severities = [s for t, s in severities.items() if "Debug Headers" in t]
        assert SeverityLevel.INFO in header_severities


if __name__ == "__main__":
    pytest.main([__file__, "-v"])