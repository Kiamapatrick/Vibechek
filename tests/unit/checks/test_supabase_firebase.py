import pytest
import base64
import json
from unittest.mock import AsyncMock, MagicMock
from vibeshield.scanner.checks.supabase_firebase import SupabaseFirebaseCheck
from vibeshield.models.recon import ReconData
from vibeshield.models.finding import SeverityLevel


def make_anon_key() -> str:
    """Create a valid Supabase anon key for testing"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"role": "anon", "iss": "supabase"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = "fake_signature"
    return f"{header_b64}.{payload_b64}.{signature}"


class TestSupabaseFirebaseCheck:
    
    @pytest.fixture
    def supabase_mock_http(self):
        """AsyncMock with configurable responses per URL/method"""
        mock = AsyncMock()
        mock.get = AsyncMock()
        mock.post = AsyncMock()
        return mock

    @pytest.fixture
    def recon(self):
        return ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[],
        )

    @pytest.fixture
    def anon_key(self):
        return make_anon_key()

    @pytest.mark.asyncio
    async def test_read_bypass_without_write_flag(self, supabase_mock_http, recon, anon_key):
        """GET returning data → HIGH finding, POST never called"""
        check = SupabaseFirebaseCheck()
        check.allow_write_tests = False
        
        # Mock GET to return row data
        supabase_mock_http.get.return_value = MagicMock(
            status_code=200,
            text='[{"id": 1, "email": "user@example.com"}]',
            headers={}
        )
        
        findings = await check._check_supabase(anon_key, recon, supabase_mock_http)
        
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH
        assert "Read Bypass" in findings[0].title
        supabase_mock_http.post.assert_not_called()  # Key assertion

    @pytest.mark.asyncio
    async def test_write_bypass_with_write_flag(self, supabase_mock_http, recon, anon_key):
        """POST returning 201 → CRITICAL finding when flag enabled"""
        check = SupabaseFirebaseCheck()
        check.allow_write_tests = True
        
        # GET returns 404/null (no read bypass), POST returns 201
        supabase_mock_http.get.return_value = MagicMock(status_code=404, text="null", headers={})
        supabase_mock_http.post.return_value = MagicMock(status_code=201, text="", headers={})
        
        findings = await check._check_supabase(anon_key, recon, supabase_mock_http)
        
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert "Bypass" in findings[0].title
        supabase_mock_http.post.assert_called()

    @pytest.mark.asyncio
    async def test_no_bypass_when_rls_works(self, supabase_mock_http, recon, anon_key):
        """GET returns 401/403 → no finding"""
        check = SupabaseFirebaseCheck()
        check.allow_write_tests = False
        
        supabase_mock_http.get.return_value = MagicMock(status_code=403, text="", headers={})
        
        findings = await check._check_supabase(anon_key, recon, supabase_mock_http)
        
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_post_not_called_when_no_read_bypass_and_flag_off(self, supabase_mock_http, recon, anon_key):
        """GET falls through every table AND flag is off -> POST must never fire."""
        check = SupabaseFirebaseCheck()
        check.allow_write_tests = False
        supabase_mock_http.get.return_value = MagicMock(status_code=404, text="null", headers={})

        await check._check_supabase(anon_key, recon, supabase_mock_http)

        supabase_mock_http.post.assert_not_called()