import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from vibeshield.utils.http import HTTPClient


class TestHTTPClient:
    @pytest.fixture
    def mock_async_client_class(self):
        with patch("vibeshield.utils.http.httpx.AsyncClient") as mock_class:
            client_instance = AsyncMock()
            mock_class.return_value = client_instance
            yield mock_class, client_instance

    @pytest.mark.asyncio
    async def test_context_manager_initializes_client(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient(timeout=5.0) as client:
            assert client._client is not None
            mock_class.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager_closes_client(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient() as client:
            pass
        client_instance.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_calls_client_get(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get("http://example.com")

        assert result == mock_response
        client_instance.get.assert_called_once_with("http://example.com")

    @pytest.mark.asyncio
    async def test_post_calls_client_post(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.post.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.post("http://example.com", json={"key": "value"})

        assert result == mock_response
        client_instance.post.assert_called_once_with("http://example.com", json={"key": "value"})

    @pytest.mark.asyncio
    async def test_head_calls_client_head(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.head.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.head("http://example.com")

        assert result == mock_response
        client_instance.head.assert_called_once_with("http://example.com")

    @pytest.mark.asyncio
    async def test_options_calls_client_options(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.options.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.options("http://example.com")

        assert result == mock_response
        client_instance.options.assert_called_once_with("http://example.com")

    @pytest.mark.asyncio
    async def test_get_text_returns_text_on_success(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock()
        mock_response.text = "hello world"
        mock_response.raise_for_status = MagicMock()
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result == "hello world"

    @pytest.mark.asyncio
    async def test_get_text_returns_none_on_http_error(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_text_returns_none_on_network_error(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        client_instance.get.side_effect = httpx.NetworkError("connection failed")

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_returns_json_on_success(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock()
        mock_response.json.return_value = {"key": "value"}
        mock_response.raise_for_status = MagicMock()
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result == {"key": "value"}
        client_instance.get.assert_called_once_with(
            "http://example.com/api",
            headers={"Accept": "application/json"}
        )

    @pytest.mark.asyncio
    async def test_get_json_returns_none_on_http_error(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_returns_none_on_invalid_json(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("invalid json")
        mock_response.raise_for_status = MagicMock()
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_json("http://example.com/api")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_returns_none_on_network_error(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        client_instance.get.side_effect = httpx.NetworkError("connection failed")

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
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient() as client:
            pass
        
        call_kwargs = mock_class.call_args.kwargs
        assert "headers" in call_kwargs
        assert "User-Agent" in call_kwargs["headers"]
        assert "VibeShield" in call_kwargs["headers"]["User-Agent"]

    @pytest.mark.asyncio
    async def test_default_headers_include_accept(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient() as client:
            pass
        
        call_kwargs = mock_class.call_args.kwargs
        assert "Accept" in call_kwargs["headers"]

    @pytest.mark.asyncio
    async def test_connection_limits_configured(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient() as client:
            pass
        
        call_kwargs = mock_class.call_args.kwargs
        assert "limits" in call_kwargs
        limits = call_kwargs["limits"]
        assert limits.max_connections == 10
        assert limits.max_keepalive_connections == 5

    @pytest.mark.asyncio
    async def test_retry_on_timeout(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.get.side_effect = [
            httpx.TimeoutException("timeout"),
            httpx.TimeoutException("timeout"),
            mock_response
        ]

        async with HTTPClient(timeout=0.1) as client:
            result = await client.get("http://example.com")

        assert result == mock_response
        assert client_instance.get.call_count == 3

    @pytest.mark.asyncio
    async def test_retry_on_network_error(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.get.side_effect = [
            httpx.NetworkError("network error"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.get("http://example.com")

        assert result == mock_response
        assert client_instance.get.call_count == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_http_status_error_in_get_text(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        client_instance.get.return_value = mock_response

        async with HTTPClient() as client:
            result = await client.get_text("http://example.com")

        assert result is None
        assert client_instance.get.call_count == 1

    @pytest.mark.asyncio
    async def test_max_retries_exceeded_raises(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        client_instance.get.side_effect = httpx.TimeoutException("timeout")

        async with HTTPClient() as client:
            with pytest.raises(httpx.TimeoutException):
                await client.get("http://example.com")

        assert client_instance.get.call_count == 3

    @pytest.mark.asyncio
    async def test_custom_timeout_passed_to_client(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient(timeout=30.0) as client:
            pass
        
        call_kwargs = mock_class.call_args.kwargs
        timeout = call_kwargs["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.connect == 5.0
        assert timeout.read == 30.0

    @pytest.mark.asyncio
    async def test_custom_max_redirects(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient(max_redirects=3) as client:
            pass
        
        call_kwargs = mock_class.call_args.kwargs
        assert call_kwargs["max_redirects"] == 3

    @pytest.mark.asyncio
    async def test_follow_redirects_enabled(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        async with HTTPClient() as client:
            pass
        
        call_kwargs = mock_class.call_args.kwargs
        assert call_kwargs["follow_redirects"] is True

    @pytest.mark.asyncio
    async def test_retry_applies_to_post(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.post.side_effect = [
            httpx.NetworkError("network error"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.post("http://example.com", json={})

        assert result == mock_response
        assert client_instance.post.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_applies_to_head(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.head.side_effect = [
            httpx.TimeoutException("timeout"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.head("http://example.com")

        assert result == mock_response
        assert client_instance.head.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_applies_to_options(self, mock_async_client_class):
        mock_class, client_instance = mock_async_client_class
        mock_response = MagicMock(spec=httpx.Response)
        client_instance.options.side_effect = [
            httpx.NetworkError("network error"),
            mock_response
        ]

        async with HTTPClient() as client:
            result = await client.options("http://example.com")

        assert result == mock_response
        assert client_instance.options.call_count == 2