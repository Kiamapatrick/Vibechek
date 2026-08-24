import pytest

from vibeshield.models.recon import CrawledPage, ReconData
from vibeshield.scanner.checks.cors import CORSCheck


class TestCORSCheck:
    @pytest.fixture
    def check(self):
        return CORSCheck()

    @pytest.fixture
    def recon_with_api(self):
        recon = ReconData(target_url="https://example.com", base_url="https://example.com")
        page = CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html="<html><body>Test</body></html>",
            headers={},
            links=["https://example.com/api/users"],
        )
        recon.pages = [page]
        return recon

    @pytest.mark.asyncio
    async def test_wildcard_cors_with_credentials(self, check, recon_with_api, mock_httpx_client):
        findings = await check.run(recon_with_api, mock_httpx_client)
        critical_findings = [f for f in findings if f.severity.value == "Critical"]
        assert len(critical_findings) > 0

    @pytest.mark.asyncio
    async def test_finding_structure(self, check, recon_with_api, mock_httpx_client):
        findings = await check.run(recon_with_api, mock_httpx_client)
        for f in findings:
            assert f.check == "cors"
            assert f.wstg_id
            assert f.attck_ids
            assert f.evidence.url
            assert "ACAO" in f.evidence.snippet or "ACAC" in f.evidence.snippet