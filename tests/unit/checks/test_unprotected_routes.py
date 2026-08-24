from unittest.mock import MagicMock

import pytest

from vibeshield.models.finding import SeverityLevel
from vibeshield.models.recon import CrawledPage, ReconData
from vibeshield.scanner.checks.unprotected_routes import UnprotectedRoutesCheck


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
        # Default response for any unhandled URL
        mock = MagicMock()
        mock.status_code = 404
        mock.text = "<html><body>Not Found</body></html>"
        mock.headers = {"content-type": "text/html"}
        mock.json = MagicMock(return_value={})  # Add json method
        return mock


def make_response(status=200, text="<html><body></body></html>", headers=None):
    mock = MagicMock()
    mock.status_code = status
    mock.text = text
    mock.headers = headers or {"content-type": "text/html"}
    # Add json method for JSON responses
    if headers and "application/json" in headers.get("content-type", ""):
        import json
        mock.json = MagicMock(return_value=json.loads(text))
    else:
        mock.json = MagicMock(return_value={})
    return mock


class TestUnprotectedRoutesCheck:
    @pytest.fixture
    def check(self):
        return UnprotectedRoutesCheck()

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
                    headers={},
                    links=["https://example.com/api/users", "https://example.com/api/admin"],
                    scripts=[],
                    forms=[],
                ),
                CrawledPage(
                    url="https://example.com/api/users",
                    depth=1,
                    status_code=200,
                    content_type="application/json",
                    html='[{"id":1,"email":"user@example.com"}]',
                    headers={},
                    links=[],
                    scripts=[],
                    forms=[],
                ),
            ],
        )

    @pytest.fixture
    def mock_http(self):
        return MockHTTPClient()

    # === Endpoint Identification Tests ===

    def test_identifies_api_endpoints_from_links(self, check, recon):
        """API endpoints are identified from page links."""
        endpoints = check._identify_api_endpoints(recon)
        assert "https://example.com/api/users" in endpoints
        assert "https://example.com/api/admin" in endpoints

    def test_identifies_api_endpoints_from_scripts(self, check, recon):
        """API endpoints are identified from script src URLs."""
        recon.pages[0].scripts = ["https://example.com/api/v1/data"]
        endpoints = check._identify_api_endpoints(recon)
        assert "https://example.com/api/v1/data" in endpoints

    def test_identifies_api_endpoints_from_forms(self, check, recon):
        """API endpoints are identified from form actions."""
        recon.pages[0].forms = [{
            "action": "/api/auth/login",
            "method": "POST",
            "inputs": [{"name": "email"}, {"name": "password"}]
        }]
        endpoints = check._identify_api_endpoints(recon)
        assert "https://example.com/api/auth/login" in endpoints

    def test_identifies_api_endpoints_from_recon(self, check, recon):
        """API endpoints from recon fingerprint are included."""
        # Fingerprint should have api_endpoints
        from vibeshield.models.recon import FingerprintResult
        recon.fingerprint = FingerprintResult(
            api_endpoints=["https://example.com/api/v1/users"]
        )
        endpoints = check._identify_api_endpoints(recon)
        assert "https://example.com/api/v1/users" in endpoints

    def test_filters_same_origin_only(self, check, recon):
        """Only same-origin endpoints are included."""
        recon.pages[0].links = [
            "https://example.com/api/users",
            "https://external.com/api/users",
        ]
        endpoints = check._identify_api_endpoints(recon)
        assert "https://example.com/api/users" in endpoints
        assert "https://external.com/api/users" not in endpoints

    def test_respects_max_limit(self, check, recon):
        """Endpoint list is capped at 30."""
        recon.pages[0].links = [f"https://example.com/api/item{i}" for i in range(50)]
        endpoints = check._identify_api_endpoints(recon)
        assert len(endpoints) <= 30

    # === Endpoint Testing Tests ===

    @pytest.mark.asyncio
    async def test_json_response_flagged_as_unprotected(self, check, recon, mock_http):
        """JSON response with sensitive data and no auth = unprotected."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='[{"id":1,"email":"user@example.com"}]',
                headers={"content-type": "application/json"}
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/users", recon, mock_http)
        assert finding is not None
        assert finding.title == "Unprotected API Endpoint: /api/users"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.7

    @pytest.mark.asyncio
    async def test_html_with_sensitive_data_flagged(self, check, recon, mock_http):
        """HTML response with sensitive data keywords = unprotected."""
        mock_http.responses = {
            "https://example.com/api/profile": make_response(
                status=200,
                text='<html><body>{"user": {"email": "test@test.com", "id": 1}}</body></html>',
                headers={"content-type": "text/html"}
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/profile", recon, mock_http)
        assert finding is not None

    @pytest.mark.asyncio
    async def test_set_cookie_auth_indicator_blocks_finding(self, check, recon, mock_http):
        """Set-Cookie with session/auth prevents finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='[{"id":1,"email":"user@example.com"}]',
                headers={
                    "content-type": "application/json",
                    "set-cookie": "session=abc123; HttpOnly"
                }
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/users", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_www_authenticate_header_blocks_finding(self, check, recon, mock_http):
        """WWW-Authenticate header prevents finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=401,
                text="Unauthorized",
                headers={"www-authenticate": "Bearer realm=api"}
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/users", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_authorization_bearer_header_blocks_finding(self, check, recon, mock_http):
        """Authorization: Bearer header in response prevents finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='[{"id":1,"email":"user@example.com"}]',
                headers={
                    "content-type": "application/json",
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                }
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/users", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_json_body_access_token_blocks_finding(self, check, recon, mock_http):
        """access_token in JSON body blocks finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "user": {"id": 1}}',
                headers={"content-type": "application/json"}
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/users", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_json_body_session_blocks_finding(self, check, recon, mock_http):
        """session in JSON body blocks finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='{"session": {"id": "abc", "user": {"id": 1}}}',
                headers={"content-type": "application/json"}
            )
        }

        finding = await check._test_endpoint("https://example.com/api/users", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_non_json_no_sensitive_data_skipped(self, check, recon, mock_http):
        """Non-JSON without sensitive keywords returns None."""
        mock_http.responses = {
            "https://example.com/api/random": make_response(
                status=200,
                text='<html><body>Welcome</body></html>',
                headers={"content-type": "text/html"}
            ),
        }

        finding = await check._test_endpoint("https://example.com/api/random", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_404_status_skipped(self, check, recon, mock_http):
        """404 status returns None."""
        mock_http.responses = {
            "https://example.com/api/missing": make_response(status=404, text="Not found"),
        }

        finding = await check._test_endpoint("https://example.com/api/missing", recon, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_500_status_skipped(self, check, recon, mock_http):
        """500 status returns None."""
        mock_http.responses = {
            "https://example.com/api/error": make_response(status=500, text="Server error"),
        }

        finding = await check._test_endpoint("https://example.com/api/error", recon, mock_http)
        assert finding is None

    # === Impact Assessment Tests ===

    def test_high_impact_for_password_secret_token(self, check):
        """Content with password/secret/token gets impact 5."""
        content = '{"password": "secret", "token": "abc"}'
        assert check._assess_impact(content) == 5

    def test_high_impact_for_ssn_credit(self, check):
        """Content with SSN/credit card gets impact 5."""
        content = '{"ssn": "123-45-6789", "credit_card": "4111"}'
        assert check._assess_impact(content) == 5

    def test_medium_impact_for_email_address_phone(self, check):
        """Content with email/address/phone gets impact 4."""
        content = '{"email": "test@test.com", "address": "123 Main St", "phone": "555-1234"}'
        assert check._assess_impact(content) == 4

    def test_medium_impact_for_order_payment_billing(self, check):
        """Content with order/payment/billing gets impact 4."""
        content = '{"order_id": 123, "payment": {"amount": 100}, "billing": {}}'
        assert check._assess_impact(content) == 4

    def test_low_impact_for_user_profile_account(self, check):
        """Content with user/profile/account/id gets impact 3."""
        content = '{"user": {"id": 1, "name": "John", "profile": {}}}'
        assert check._assess_impact(content) == 3

    def test_default_impact(self, check):
        """Content without sensitive keywords gets impact 2."""
        content = '{"data": "generic"}'
        assert check._assess_impact(content) == 2

    # === Integration Tests ===

    @pytest.mark.asyncio
    async def test_run_integration_unprotected(self, check, recon, mock_http):
        """Full run detects unprotected endpoint."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='[{"id":1,"email":"user@example.com"}]',
                headers={"content-type": "application/json"}
            ),
        }

        findings = await check.run(recon, mock_http)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_run_integration_protected_by_bearer(self, check, recon, mock_http):
        """Bearer token in response prevents finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='[{"id":1,"email":"user@example.com"}]',
                headers={
                    "content-type": "application/json",
                    "authorization": "Bearer token123"
                }
            ),
        }

        findings = await check.run(recon, mock_http)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_with_access_token_in_body(self, check, recon, mock_http):
        """access_token in response body blocks finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}',
                headers={"content-type": "application/json"}
            ),
        }

        findings = await check.run(recon, mock_http)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_with_session_in_body(self, check, recon, mock_http):
        """session in response body blocks finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='{"session": {"id": "abc123", "user_id": 1}}',
                headers={"content-type": "application/json"}
            ),
        }

        findings = await check.run(recon, mock_http)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_run_id_token_in_body(self, check, recon, mock_http):
        """id_token in response body blocks finding."""
        mock_http.responses = {
            "https://example.com/api/users": make_response(
                status=200,
                text='{"id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"}',
                headers={"content-type": "application/json"}
            )
        }

        findings = await check.run(recon, mock_http)
        assert len(findings) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])