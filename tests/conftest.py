import pytest


@pytest.fixture
def sample_html():
    return """
    <html>
    <head><title>Test App</title></head>
    <body>
        <script src="/_next/static/chunks/main.js"></script>
        <script>
            const apiKey = "AKIA1234567890ABCDEF";
            const config = { apiKey: "sk_test_fake_key_for_testing_only" };
        </script>
        <a href="/api/users">Users API</a>
        <a href="/dashboard">Dashboard</a>
        <form action="/api/auth/login" method="POST">
            <input name="email" type="email" required>
            <input name="password" type="password" required>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """


@pytest.fixture
def sample_js():
    return """
    const API_KEY = "AKIA1234567890ABCDEF";
    const SECRET = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
    export default { API_KEY, SECRET };
    """


@pytest.fixture
def sample_headers():
    return {
        "content-type": "text/html; charset=utf-8",
        "server": "nginx/1.18.0",
        "x-powered-by": "Express",
    }


@pytest.fixture
def mock_http_response(sample_html, sample_headers):
    class MockResponse:
        def __init__(self, text, status_code=200, headers=None, url=""):
            self.text = text
            self.status_code = status_code
            self.headers = headers or sample_headers
            self.url = url

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP {self.status_code}")

    return MockResponse


@pytest.fixture
def mock_httpx_client(mock_http_response, sample_html, sample_js, sample_headers):
    class MockClient:
        def __init__(self):
            self.call_count = 0

        async def get(self, url, **kwargs):
            self.call_count += 1
            if url.endswith(".js"):
                return mock_http_response(sample_js, 200, {"content-type": "application/javascript"}, url)
            if "/.env" in url:
                return mock_http_response("API_KEY=secret\n", 200, {"content-type": "text/plain"}, url)
            return mock_http_response(sample_html, 200, sample_headers, url)

        async def post(self, url, **kwargs):
            self.call_count += 1
            return mock_http_response("ok", 200, sample_headers, url)

        async def options(self, url, **kwargs):
            self.call_count += 1
            return mock_http_response("", 200, {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }, url)

        async def head(self, url, **kwargs):
            return mock_http_response("", 200, sample_headers, url)

        async def aclose(self):
            pass

    return MockClient()


@pytest.fixture
def event_loop():
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()