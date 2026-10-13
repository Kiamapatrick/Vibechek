import types
from typing import Any, Self

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from vibeshield.config import settings
from vibeshield.utils.validation import validate_target_or_raise


class HTTPClient:
    def __init__(
        self,
        timeout: float = 10.0,
        max_redirects: int = 5,
        allow_private_targets: bool = True,
    ):
        self.timeout = httpx.Timeout(timeout, connect=5.0)
        self.max_redirects = max_redirects
        self.allow_private_targets = allow_private_targets
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Self:
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            headers={
                "User-Agent": f"VibeShield/{settings.VERSION} (+https://github.com/vibeshield/vibeshield)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if not self._client:
            raise RuntimeError("HTTPClient not initialized. Use async context manager.")
        return self._client

    def _validate_url(self, url: str) -> None:
        validate_target_or_raise(url, self.allow_private_targets)

    async def _request_with_redirects(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Perform HTTP request with manual redirect following and validation at each hop."""
        current_url = url
        redirects_followed = 0

        while True:
            self._validate_url(current_url)

            resp = await self._request_with_retry(method, current_url, **kwargs)

            if 300 <= resp.status_code < 400 and "location" in resp.headers and redirects_followed < self.max_redirects:
                redirects_followed += 1
                location = resp.headers["location"]
                current_url = str(httpx.URL(current_url).join(location))
                continue

            return resp

    @retry(
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        reraise=True,
    )
    async def _request_with_retry(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return await self.client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request_with_redirects("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request_with_redirects("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request_with_redirects("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request_with_redirects("OPTIONS", url, **kwargs)

    async def get_text(self, url: str) -> str | None:
        try:
            resp = await self.get(url)
            resp.raise_for_status()
            return resp.text
        except httpx.HTTPError:
            return None

    async def get_json(self, url: str) -> dict[str, Any] | None:
        try:
            resp = await self.get(url, headers={"Accept": "application/json"})
            resp.raise_for_status()
            return resp.json()  # type: ignore[no-any-return]
        except (httpx.HTTPError, ValueError):
            return None