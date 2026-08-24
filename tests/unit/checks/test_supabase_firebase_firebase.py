import pytest
from unittest.mock import AsyncMock, MagicMock
from vibeshield.scanner.checks.supabase_firebase import SupabaseFirebaseCheck
from vibeshield.models.recon import ReconData
from vibeshield.models.finding import SeverityLevel
from vibeshield.utils.http import HTTPClient


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
        mock.text = "Not Found"
        mock.headers = {"content-type": "text/plain"}
        mock.json = MagicMock(return_value={})
        return mock


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


class TestSupabaseFirebaseCheckFirebase:
    @pytest.fixture
    def check(self):
        return SupabaseFirebaseCheck()

    @pytest.fixture
    def recon(self):
        return ReconData(
            target_url="https://example.com",
            base_url="https://example.com",
            pages=[],
        )

    @pytest.fixture
    def mock_http(self):
        return MockHTTPClient()

    @pytest.fixture
    def project_id(self):
        return "test-project-123"

    # === Firebase Realtime Database Tests ===

    @pytest.mark.asyncio
    async def test_realtime_db_publicly_readable(self, check, recon, mock_http, project_id):
        """Publicly readable Realtime DB triggers CRITICAL finding."""
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(
                status=200,
                text='{"users": {"user1": {"email": "test@test.com"}}}',
                headers={"content-type": "application/json"}
            ),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is not None
        assert finding.title == "Firebase Realtime Database Publicly Readable"
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.confidence == 0.9
        assert "auth != null" in finding.remediation

    @pytest.mark.asyncio
    async def test_realtime_db_null_response_no_finding(self, check, recon, mock_http, project_id):
        """Null response from Realtime DB produces no finding."""
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(
                status=200,
                text="null",
                headers={"content-type": "application/json"}
            ),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_realtime_db_empty_response_no_finding(self, check, recon, mock_http, project_id):
        """Empty response from Realtime DB produces no finding."""
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(
                status=200,
                text="",
                headers={"content-type": "application/json"}
            ),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_realtime_db_404_no_finding(self, check, recon, mock_http, project_id):
        """404 from Realtime DB produces no finding."""
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(status=404, text="Not found"),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_realtime_db_network_error_no_finding(self, check, recon, mock_http, project_id):
        """Network error from Realtime DB produces no finding."""
        mock_http.responses = {}  # Will return 404 default

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is None

    # === Firestore Tests ===

    @pytest.mark.asyncio
    async def test_firestore_accessible_without_auth(self, check, recon, mock_http, project_id):
        """Firestore accessible without auth triggers HIGH finding."""
        mock_http.responses = {
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents": make_response(
                status=200,
                text='{"documents": [{"name": "projects/test-project-123/databases/(default)/documents/users/user1"}]}',
                headers={"content-type": "application/json"}
            ),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is not None
        assert finding.title == "Firestore API Accessible Without Authentication"
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == 0.75
        assert "authentication" in finding.remediation.lower()

    @pytest.mark.asyncio
    async def test_firestore_404_no_finding(self, check, recon, mock_http, project_id):
        """404 from Firestore produces no finding."""
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(status=404),
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents": make_response(status=404),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is None

    @pytest.mark.asyncio
    async def test_firestore_network_error_no_finding(self, check, recon, mock_http, project_id):
        """Network error from Firestore produces no finding."""
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(status=404),
        }

        finding = await check._test_firebase_access(project_id, mock_http)
        assert finding is None

    # === Integration Tests ===

    @pytest.mark.asyncio
    async def test_check_firebase_integration_realtime_db(self, check, recon, mock_http):
        """Full check_firebase detects publicly readable Realtime DB."""
        project_id = "test-project-123"
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(
                status=200,
                text='{"data": "sensitive"}',
                headers={"content-type": "application/json"}
            ),
        }

        # Need to inject project_id into recon content
        from vibeshield.models.recon import CrawledPage
        recon.pages = [CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html=f'<html><script>firebaseConfig = {{ projectId: "{project_id}" }}</script></html>',
            headers={},
            scripts=[],
        )]

        findings = await check._check_firebase(f"firebaseConfig = {{ projectId: \"{project_id}\" }}", recon, mock_http)
        assert len(findings) == 1
        assert findings[0].title == "Firebase Realtime Database Publicly Readable"

    @pytest.mark.asyncio
    async def test_check_firebase_integration_firestore(self, check, recon, mock_http):
        """Full check_firebase detects accessible Firestore."""
        project_id = "test-project-123"
        mock_http.responses = {
            f"https://{project_id}-default-rtdb.firebaseio.com/.json": make_response(status=404),
            f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents": make_response(
                status=200,
                text='{"documents": []}',
                headers={"content-type": "application/json"}
            ),
        }

        from vibeshield.models.recon import CrawledPage
        recon.pages = [CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html=f'<html><script>firebaseConfig = {{ projectId: "{project_id}" }}</script></html>',
            headers={},
            scripts=[],
        )]

        findings = await check._check_firebase(f'firebaseConfig = {{ projectId: "{project_id}" }}', recon, mock_http)
        assert len(findings) == 1
        assert findings[0].title == "Firestore API Accessible Without Authentication"

    @pytest.mark.asyncio
    async def test_check_firebase_multiple_project_ids(self, check, recon, mock_http):
        """Multiple Firebase project IDs are checked."""
        mock_http.responses = {
            "https://project-a-default-rtdb.firebaseio.com/.json": make_response(status=200, text='{"data": "a"}'),
            "https://project-b-default-rtdb.firebaseio.com/.json": make_response(status=404),
        }

        content = 'firebaseConfig = { projectId: "project-a" } firebaseConfig = { projectId: "project-b" }'

        from vibeshield.models.recon import CrawledPage
        recon.pages = [CrawledPage(
            url="https://example.com",
            depth=0,
            status_code=200,
            content_type="text/html",
            html=content,
            headers={},
            scripts=[],
        )]

        findings = await check._check_firebase(content, recon, mock_http)
        assert len(findings) == 1
        assert "project-a" in findings[0].evidence.matched_pattern


if __name__ == "__main__":
    pytest.main([__file__, "-v"])