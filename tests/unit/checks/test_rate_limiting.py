import pytest

from vibeshield.models.recon import CrawledPage, ReconData
from vibeshield.scanner.checks.rate_limiting import RateLimitingCheck


class TestRateLimitingCheck:
    @pytest.fixture
    def check(self):
        return RateLimitingCheck()

    @pytest.fixture
    def recon_with_login(self):
        recon = ReconData(target_url="https://example.com", base_url="https://example.com")
        page = CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html="""
            <html><body>
            <form action="/api/auth/login" method="POST">
                <input name="email" type="email">
                <input name="password" type="password">
            </form>
            </body></html>
            """,
            headers={},
            forms=[{
                "action": "https://example.com/api/auth/login",
                "method": "POST",
                "inputs": [{"name": "email"}, {"name": "password"}],
            }],
        )
        recon.pages = [page]
        return recon

    @pytest.mark.asyncio
    async def test_detects_no_rate_limit(self, check, recon_with_login, mock_httpx_client):
        findings = await check.run(recon_with_login, mock_httpx_client)
        assert len(findings) > 0
        assert findings[0].check == "rate_limiting"
        assert findings[0].severity.value in ("High", "Critical")

    @pytest.mark.asyncio
    async def test_finding_structure(self, check, recon_with_login, mock_httpx_client):
        findings = await check.run(recon_with_login, mock_httpx_client)
        for f in findings:
            assert f.wstg_id
            assert f.attck_ids
            assert "rate" in f.title.lower() or "limit" in f.title.lower()
            assert f.remediation
            assert "rate limit" in f.remediation.lower()