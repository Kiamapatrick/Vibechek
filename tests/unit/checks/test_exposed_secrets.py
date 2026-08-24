import pytest

from vibeshield.models.recon import ReconData
from vibeshield.scanner.checks.exposed_secrets import ExposedSecretsCheck


class TestExposedSecretsCheck:
    @pytest.fixture
    def check(self):
        return ExposedSecretsCheck()

    @pytest.fixture
    def recon(self, sample_html, sample_js):
        recon = ReconData(target_url="https://example.com", base_url="https://example.com")
        recon.pages = []
        from vibeshield.models.recon import CrawledPage
        page = CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html=sample_html,
            headers={},
            scripts=["https://example.com/_next/static/chunks/main.js"],
        )
        recon.pages.append(page)
        return recon

    @pytest.mark.asyncio
    async def test_finds_aws_key_in_js(self, check, recon, mock_httpx_client):
        findings = await check.run(recon, mock_httpx_client)
        aws_findings = [f for f in findings if "aws" in f.title.lower()]
        assert len(aws_findings) > 0
        assert aws_findings[0].severity.value == "Critical"

    @pytest.mark.asyncio
    async def test_finds_github_token(self, check, recon, mock_httpx_client):
        findings = await check.run(recon, mock_httpx_client)
        gh_findings = [f for f in findings if "github" in f.title.lower()]
        assert len(gh_findings) > 0

    @pytest.mark.asyncio
    async def test_checks_env_file(self, check, recon, mock_httpx_client):
        findings = await check.run(recon, mock_httpx_client)
        env_findings = [f for f in findings if ".env" in f.title.lower()]
        assert len(env_findings) > 0

    @pytest.mark.asyncio
    async def test_confidence_values(self, check, recon, mock_httpx_client):
        findings = await check.run(recon, mock_httpx_client)
        for f in findings:
            assert 0 <= f.confidence <= 1
            assert f.check == "exposed_secrets"
            assert f.wstg_id
            assert f.attck_ids

    @pytest.mark.asyncio
    async def test_remediation_present(self, check, recon, mock_httpx_client):
        findings = await check.run(recon, mock_httpx_client)
        for f in findings:
            assert f.remediation
            assert len(f.remediation) > 10
            assert f.references