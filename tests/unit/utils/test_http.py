from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vibeshield.utils.http import HTTPClient
from vibeshield.utils.validation import validate_target, validate_target_or_raise


def _make_mock_response(status_code: int = 200, headers: dict | None = None) -> MagicMock:
    """Create a mock response with proper attributes."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    return resp


class TestHTTPClient:
    @pytest.fixture(autouse=True)
    def _stub_dns(self):
        """SSRF validation resolves hostnames; keep these unit tests offline and deterministic."""
        public_ip = [(2, 1, 6, "", ("93.184.216.34", 0))]
        with patch("vibeshield.utils.validation.socket.getaddrinfo", return_value=public_ip):
            yield

    @pytest.fixture
    def mock_async_client_class(self):
        with patch("vibeshield.utils.http.httpx.AsyncClient") as mock_class:
            client_instance = AsyncMock()
            mock_class.return_value = client_instance
            yield mock_class, client_instance

    @pytest.mark.asyncio
    async def test_context_manager_initializes_client(self, mock_async_client_class):
        mock_class, _ = mock_async_client_class
        async with HTTPClient(timeout=5.0) as _:
            assert _.client is not None
            mock_class.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager_closes_client(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        async with HTTPClient():
            pass
        client_instance.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_calls_client_request(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get("http://example.com")

        assert result == mock_response
        client_instance.request.assert_called_once_with("GET", "http://example.com")

    @pytest.mark.asyncio
    async def test_post_calls_client_request(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.post("http://example.com", json={"key": "value"})

        assert result == mock_response
        client_instance.request.assert_called_once_with("POST", "http://example.com", json={"key": "value"})

    @pytest.mark.asyncio
    async def test_head_calls_client_request(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.head("http://example.com")

        assert result == mock_response
        client_instance.request.assert_called_once_with("HEAD", "http://example.com")

    @pytest.mark.asyncio
    async def test_options_calls_client_request(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.options("http://example.com")

        assert result == mock_response
        client_instance.request.assert_called_once_with("OPTIONS", "http://example.com")

    @pytest.mark.asyncio
    async def test_get_text_returns_text_on_success(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        mock_response.text = "hello world"
        mock_response.raise_for_status = MagicMock()
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result == "hello world"

    @pytest.mark.asyncio
    async def test_get_text_returns_none_on_http_error(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(404)
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_text_returns_none_on_network_error(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        client_instance.request.side_effect = httpx.NetworkError("connection failed")

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_returns_json_on_success(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        mock_response.json.return_value = {"key": "value"}
        mock_response.raise_for_status = MagicMock()
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result == {"key": "value"}
        client_instance.request.assert_called_once_with(
            "GET", "http://example.com/api", headers={"Accept": "application/json"}
        )

    @pytest.mark.asyncio
    async def test_get_json_returns_none_on_http_error(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(500)
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_returns_none_on_invalid_json(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        mock_response.json.side_effect = ValueError("invalid json")
        mock_response.raise_for_status = MagicMock()
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_returns_none_on_network_error(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        client_instance.request.side_effect = httpx.NetworkError("connection failed")

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result is None

    @pytest.mark.asyncio
    async def test_client_property_raises_when_not_initialized(self):
        client = HTTPClient()
        with pytest.raises(RuntimeError, match="HTTPClient not initialized"):
            _ = client.client

    @pytest.mark.asyncio
    async def test_default_headers_include_user_agent(self, mock_async_client_class):
        mock_class, _ = mock_async_client_class
        async with HTTPClient():
            pass

        call_kwargs = mock_class.call_args.kwargs
        assert "headers" in call_kwargs
        assert "User-Agent" in call_kwargs["headers"]
        assert "VibeShield" in call_kwargs["headers"]["User-Agent"]

    @pytest.mark.asyncio
    async def test_default_headers_include_accept(self, mock_async_client_class):
        mock_class, _ = mock_async_client_class
        async with HTTPClient():
            pass

        call_kwargs = mock_class.call_args.kwargs
        assert "Accept" in call_kwargs["headers"]

    @pytest.mark.asyncio
    async def test_connection_limits_configured(self, mock_async_client_class):
        mock_class, _ = mock_async_client_class
        async with HTTPClient():
            pass

        call_kwargs = mock_class.call_args.kwargs
        assert "limits" in call_kwargs
        limits = call_kwargs["limits"]
        assert limits.max_connections == 10
        assert limits.max_keepalive_connections == 5

    @pytest.mark.asyncio
    async def test_retry_on_timeout(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.side_effect = [
            httpx.TimeoutException("timeout"),
            httpx.TimeoutException("timeout"),
            mock_response
        ]

        async with HTTPClient(timeout=0.1) as client:
            result = await client.get("http://example.com")

        assert result == mock_response
        assert client_instance.request.call_count == 3

    @pytest.mark.asyncio
    async def test_retry_on_network_error(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.side_effect = [
            httpx.NetworkError("network error"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.get("http://example.com")

        assert result == mock_response
        assert client_instance.request.call_count == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_http_status_error_in_get_text(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(404)
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        client_instance.request.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result is None
        assert client_instance.request.call_count == 1

    @pytest.mark.asyncio
    async def test_max_retries_exceeded_raises(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        client_instance.request.side_effect = httpx.TimeoutException("timeout")

        async with HTTPClient() as client:
            with pytest.raises(httpx.TimeoutException):
                await client.get("http://example.com")

        assert client_instance.request.call_count == 3

    @pytest.mark.asyncio
    async def test_custom_timeout_passed_to_client(self, mock_async_client_class):
        mock_class, _ = mock_async_client_class
        async with HTTPClient(timeout=30.0):
            pass

        call_kwargs = mock_class.call_args.kwargs
        timeout = call_kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.connect == 5.0
        assert timeout.read == 30.0

    @pytest.mark.asyncio
    async def test_allow_private_targets_default_true(self, mock_async_client_class):
        """CLI default: allow private targets."""
        _, _ = mock_async_client_class
        async with HTTPClient():
            pass

        # Default should be True for CLI usage
        client = HTTPClient()
        assert client.allow_private_targets is True

    @pytest.mark.asyncio
    async def test_allow_private_targets_can_be_false(self, mock_async_client_class):
        """Backend usage: disallow private targets."""
        _, _ = mock_async_client_class
        async with HTTPClient(allow_private_targets=False):
            pass

        client = HTTPClient(allow_private_targets=False)
        assert client.allow_private_targets is False

    @pytest.mark.asyncio
    async def test_follow_redirects(self, mock_async_client_class):
        """Test that redirects are followed manually with validation."""
        _, client_instance = mock_async_client_class

        # First response: 302 redirect
        redirect_response = _make_mock_response(302, {"location": "https://example.com/new-path"})

        # Second response: final 200
        final_response = _make_mock_response(200)

        client_instance.request.side_effect = [redirect_response, final_response]

        async with HTTPClient() as client:
            result = await client.get("https://example.com/old-path")

        assert result == final_response
        assert client_instance.request.call_count == 2

    @pytest.mark.asyncio
    async def test_max_redirects_limit(self, mock_async_client_class):
        """Test that max_redirects is respected."""
        _, client_instance = mock_async_client_class

        # Always return redirect
        redirect_response = _make_mock_response(302, {"location": "https://example.com/next"})

        client_instance.request.return_value = redirect_response

        async with HTTPClient(max_redirects=2) as client:
            result = await client.get("https://example.com/start")

        # Should follow max_redirects times then return the last redirect response
        assert client_instance.request.call_count == 3  # initial + 2 redirects
        assert result == redirect_response

    @pytest.mark.asyncio
    async def test_retry_applies_to_post(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.side_effect = [
            httpx.NetworkError("network error"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.post("http://example.com", json={})

        assert result == mock_response
        assert client_instance.request.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_applies_to_head(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.side_effect = [
            httpx.TimeoutException("timeout"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.head("http://example.com")

        assert result == mock_response
        assert client_instance.request.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_applies_to_options(self, mock_async_client_class):
        _, client_instance = mock_async_client_class
        mock_response = _make_mock_response(200)
        client_instance.request.side_effect = [
            httpx.NetworkError("network error"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.options("http://example.com")

        assert result == mock_response
        assert client_instance.request.call_count == 2


class TestValidation:
    """Tests for SSRF validation in vibeshield.utils.validation."""

    def test_validate_invalid_scheme_rejected(self):
        """Non-HTTP/HTTPS schemes should be rejected."""
        valid, error = validate_target("ftp://example.com")
        assert not valid
        assert "ftp" in error.lower() or "scheme" in error.lower()

    def test_validate_localhost_rejected_by_default(self):
        """Localhost should be rejected when allow_private=False."""
        valid, error = validate_target("http://localhost:8080", allow_private=False)
        assert not valid
        assert "disallowed" in error.lower() or "private" in error.lower()

    def test_validate_localhost_allowed_when_private_allowed(self):
        """Localhost should be allowed when allow_private=True."""
        valid, error = validate_target("http://localhost:8080", allow_private=True)
        assert valid
        assert error is None

    def test_validate_private_ip_rejected_by_default(self):
        """Private IP addresses should be rejected when allow_private=False."""
        valid, _ = validate_target("http://192.168.1.1", allow_private=False)
        assert not valid

    def test_validate_private_ip_allowed_when_private_allowed(self):
        """Private IP addresses should be allowed when allow_private=True."""
        valid, _ = validate_target("http://192.168.1.1", allow_private=True)
        assert valid

    def test_validate_metadata_ip_rejected(self):
        """AWS metadata IP (169.254.169.254) should always be rejected."""
        valid, _ = validate_target("http://169.254.169.254", allow_private=False)
        assert not valid

    def test_validate_loopback_rejected(self):
        """Loopback addresses should be rejected."""
        valid, _ = validate_target("http://127.0.0.1", allow_private=False)
        assert not valid

    def test_validate_link_local_rejected(self):
        """Link-local addresses (169.254.x.x) should be rejected."""
        valid, _ = validate_target("http://169.254.1.1", allow_private=False)
        assert not valid

    def test_validate_invalid_hostname(self):
        """Invalid/unresolvable hostnames should be rejected."""
        valid, error = validate_target("http://this-domain-definitely-does-not-exist-12345.com")
        assert not valid
        assert "resolve" in error.lower() or "failed" in error.lower()


class TestValidateTargetOrRaise:
    def test_raises_on_invalid(self):
        with pytest.raises(ValueError, match="disallowed address"):
            validate_target_or_raise("http://localhost:8080", allow_private=False)