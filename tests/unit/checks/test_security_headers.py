import pytest

from vibeshield.models.finding import SeverityLevel
from vibeshield.models.recon import CrawledPage, ReconData
from vibeshield.scanner.checks.security_headers import SecurityHeadersCheck


class TestSecurityHeadersCheck:
    @pytest.fixture
    def check(self):
        return SecurityHeadersCheck()

    @pytest.fixture
    def recon_no_headers(self):
        recon = ReconData(target_url="https://example.com", base_url="https://example.com")
        page = CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html="<html><body>Test</body></html>",
            headers={"content-type": "text/html"},
        )
        recon.pages = [page]
        return recon

    @pytest.fixture
    def recon_with_csp(self):
        recon = ReconData(target_url="https://example.com", base_url="https://example.com")
        page = CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html="<html><body>Test</body></html>",
            headers={
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'",
            },
        )
        recon.pages = [page]
        return recon

    @pytest.fixture
    def recon_with_hsts(self):
        recon = ReconData(target_url="https://example.com", base_url="https://example.com")
        page = CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html="<html><body>Test</body></html>",
            headers={
                "content-type": "text/html",
                "strict-transport-security": "max-age=31536000",
            },
        )
        recon.pages = [page]
        return recon

    @pytest.mark.asyncio
    async def test_missing_csp(self, check, recon_no_headers):
        findings = await check.run(recon_no_headers, None)
        csp_findings = [f for f in findings if "content-security-policy" in f.title.lower()]
        assert len(csp_findings) > 0
        assert csp_findings[0].severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH)

    @pytest.mark.asyncio
    async def test_missing_hsts(self, check, recon_no_headers):
        findings = await check.run(recon_no_headers, None)
        hsts_findings = [f for f in findings if "hsts" in f.title.lower() or "strict-transport" in f.title.lower()]
        assert len(hsts_findings) > 0

    @pytest.mark.asyncio
    async def test_csp_present_no_finding(self, check, recon_with_csp):
        findings = await check.run(recon_with_csp, None)
        csp_findings = [f for f in findings if "content-security-policy" in f.title.lower() and "missing" in f.title.lower()]
        assert len(csp_findings) == 0

    @pytest.mark.asyncio
    async def test_hsts_present_no_finding(self, check, recon_with_hsts):
        findings = await check.run(recon_with_hsts, None)
        hsts_findings = [f for f in findings if "hsts" in f.title.lower() and "missing" in f.title.lower()]
        assert len(hsts_findings) == 0

    @pytest.mark.asyncio
    async def test_server_header_disclosure(self, check, recon_no_headers):
        page = recon_no_headers.pages[0]
        page.headers["server"] = "nginx/1.18.0"
        page.headers["x-powered-by"] = "Express"
        findings = await check.run(recon_no_headers, None)
        disclosure = [f for f in findings if "disclosure" in f.title.lower() or "version" in f.title.lower()]
        assert len(disclosure) > 0