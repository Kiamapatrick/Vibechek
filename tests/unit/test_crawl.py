import pytest
from unittest.mock import AsyncMock, MagicMock
from vibeshield.scanner.crawl import Crawler
from vibeshield.scanner.recon import Reconnaissance
from vibeshield.models.recon import CrawledPage, ReconData, FingerprintResult
from vibeshield.utils.http import HTTPClient


class MockHTTPClient:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.call_count = 0

    def _normalize_url(self, url):
        """Normalize URL for matching - strip trailing slash."""
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
        return mock


def make_response(status=200, text="<html><body></body></html>", headers=None):
    """Helper to create a MagicMock response."""
    mock = MagicMock()
    mock.status_code = status
    mock.text = text
    mock.headers = headers or {"content-type": "text/html"}
    return mock


def normalize_url(url):
    """Normalize URL for test assertions - no trailing slash."""
    return url.rstrip('/')


class TestCrawler:
    @pytest.fixture
    def base_url(self):
        return "https://example.com"

    @pytest.fixture
    def mock_http(self):
        return MockHTTPClient()

    @pytest.mark.asyncio
    async def test_crawl_starts_at_base_url(self, base_url, mock_http):
        """Crawler starts at the base URL."""
        mock_http.responses = {
            "https://example.com": make_response(text="<html><body>Home</body></html>"),
        }
        crawler = Crawler(base_url=base_url, max_depth=1, max_pages=5)
        recon = await crawler.crawl(mock_http)

        assert recon.target_url == base_url
        assert len(recon.pages) >= 1
        assert normalize_url(recon.pages[0].url) == normalize_url(base_url)

    @pytest.mark.asyncio
    async def test_respects_max_depth(self, base_url, mock_http):
        """Crawler respects max_depth limit."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><body><a href="/page1">Page 1</a></body></html>'
            ),
            "https://example.com/page1": make_response(
                text='<html><body><a href="/page2">Page 2</a></body></html>'
            ),
            "https://example.com/page2": make_response(
                text='<html><body></body></html>'
            ),
        }

        crawler = Crawler(base_url=base_url, max_depth=1, max_pages=10)
        recon = await crawler.crawl(mock_http)

        urls = {p.url for p in recon.pages}
        assert normalize_url(base_url) in {normalize_url(u) for u in urls}
        assert "https://example.com/page1" in urls
        assert "https://example.com/page2" not in urls

    @pytest.mark.asyncio
    async def test_respects_max_pages(self, base_url, mock_http):
        """Crawler respects max_pages limit."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><body><a href="/p1">P1</a><a href="/p2">P2</a><a href="/p3">P3</a><a href="/p4">P4</a><a href="/p5">P5</a></body></html>'
            ),
        }
        for i in range(1, 6):
            mock_http.responses[f"https://example.com/p{i}"] = make_response(text=f"<html><body>Page {i}</body></html>")

        crawler = Crawler(base_url=base_url, max_depth=2, max_pages=3)
        recon = await crawler.crawl(mock_http)

        assert len(recon.pages) <= 3

    @pytest.mark.asyncio
    async def test_same_origin_only(self, base_url, mock_http):
        """Crawler only follows same-origin links."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><body><a href="/internal">Internal</a><a href="https://external.com">External</a></body></html>'
            ),
            "https://example.com/internal": make_response(text="<html><body>Internal</body></html>"),
        }

        crawler = Crawler(base_url=base_url, max_depth=2, max_pages=10)
        recon = await crawler.crawl(mock_http)

        urls = {p.url for p in recon.pages}
        assert "https://example.com/internal" in urls
        assert "https://external.com" not in urls

    @pytest.mark.asyncio
    async def test_extracts_links(self, base_url, mock_http):
        """Crawler extracts links from anchor tags."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>'
            ),
            "https://example.com/page1": make_response(text="<html></html>"),
            "https://example.com/page2": make_response(text="<html></html>"),
        }

        crawler = Crawler(base_url=base_url, max_depth=1, max_pages=5)
        recon = await crawler.crawl(mock_http)

        page = next(p for p in recon.pages if normalize_url(p.url) == normalize_url(base_url))
        assert "/page1" in str(page.links)
        assert "/page2" in str(page.links)

    @pytest.mark.asyncio
    async def test_extracts_scripts(self, base_url, mock_http):
        """Crawler extracts script src URLs."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><head><script src="/app.js"></script></head><body></body></html>'
            ),
        }

        crawler = Crawler(base_url=base_url, max_depth=1, max_pages=5)
        recon = await crawler.crawl(mock_http)

        page = recon.pages[0]
        assert "https://example.com/app.js" in page.scripts

    @pytest.mark.asyncio
    async def test_extracts_forms(self, base_url, mock_http):
        """Crawler extracts form information."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><body><form action="/login" method="POST"><input name="email" type="email"><input name="password" type="password"></form></body></html>'
            ),
        }

        crawler = Crawler(base_url=base_url, max_depth=1, max_pages=5)
        recon = await crawler.crawl(mock_http)

        page = recon.pages[0]
        assert len(page.forms) == 1
        assert page.forms[0]["action"] == "https://example.com/login"
        assert page.forms[0]["method"] == "POST"
        assert any(inp["name"] == "email" for inp in page.forms[0]["inputs"])

    @pytest.mark.asyncio
    async def test_skips_non_html(self, base_url, mock_http):
        """Crawler skips non-HTML responses."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='{"data": "json"}',
                headers={"content-type": "application/json"}
            ),
        }

        crawler = Crawler(base_url=base_url, max_depth=1, max_pages=5)
        recon = await crawler.crawl(mock_http)

        assert len(recon.pages) == 0

    @pytest.mark.asyncio
    async def test_normalize_url_handles_relative(self, base_url):
        """_normalize_url handles relative URLs."""
        crawler = Crawler(base_url=base_url)
        assert crawler._normalize_url("/path") == "https://example.com/path"
        assert crawler._normalize_url("path") == "https://example.com/path"
        assert crawler._normalize_url("../path") == "https://example.com/path"

    @pytest.mark.asyncio
    async def test_normalize_url_strips_fragment(self, base_url):
        """_normalize_url strips URL fragments."""
        crawler = Crawler(base_url=base_url)
        assert crawler._normalize_url("/page#section") == "https://example.com/page"

    @pytest.mark.asyncio
    async def test_normalize_url_rejects_schemes(self, base_url):
        """_normalize_url rejects non-http schemes."""
        crawler = Crawler(base_url=base_url)
        assert crawler._normalize_url("mailto:test@example.com") is None
        assert crawler._normalize_url("tel:+1234567890") is None
        assert crawler._normalize_url("javascript:alert(1)") is None
        assert crawler._normalize_url("#anchor") is None
        assert crawler._normalize_url("data:text/html,<html>") is None

    @pytest.mark.asyncio
    async def test_is_same_origin(self):
        """_is_same_origin correctly identifies same-origin URLs."""
        crawler = Crawler(base_url="https://example.com")
        assert crawler._is_same_origin("https://example.com/page") is True
        assert crawler._is_same_origin("https://example.com/page") is True
        assert crawler._is_same_origin("https://other.com/page") is False
        assert crawler._is_same_origin("http://example.com/page") is True  # same origin, different scheme


class TestReconnaissance:
    @pytest.fixture
    def mock_http(self):
        return MockHTTPClient()

    def make_html_response(self, text, headers=None):
        return make_response(text=text, headers=headers)

    @pytest.mark.asyncio
    async def test_reconnaissance_runs_crawler(self, mock_http):
        """Reconnaissance runs crawler and returns ReconData."""
        mock_http.responses = {
            "https://example.com": make_response(text="<html><body></body></html>"),
        }
        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert isinstance(result, ReconData)
        assert result.target_url == "https://example.com"
        assert result.base_url == "https://example.com"
        assert isinstance(result.fingerprint, FingerprintResult)

    @pytest.mark.asyncio
    async def test_fingerprint_detects_nextjs(self, mock_http):
        """Fingerprint detects Next.js from __NEXT_DATA__."""
        html = '<html><head><script id="__NEXT_DATA__" type="application/json">{}</script></head></html>'
        mock_http.responses = {
            "https://example.com": make_response(text=html),
        }

        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert result.fingerprint.framework == "nextjs"

    @pytest.mark.asyncio
    async def test_fingerprint_detects_supabase(self, mock_http):
        """Fingerprint detects Supabase from client patterns."""
        html = '<html><script>import { createClient } from "@supabase/supabase-js"</script></html>'
        mock_http.responses = {
            "https://example.com": make_response(text=html),
        }

        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert "supabase" in result.fingerprint.baas

    @pytest.mark.asyncio
    async def test_fingerprint_detects_firebase(self, mock_http):
        """Fingerprint detects Firebase from config patterns."""
        html = '<html><script>firebaseConfig = { apiKey: "test" }</script></html>'
        mock_http.responses = {
            "https://example.com": make_response(text=html),
        }

        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert "firebase" in result.fingerprint.baas

    @pytest.mark.asyncio
    async def test_fingerprint_collects_headers(self, mock_http):
        """Fingerprint collects response headers."""
        mock_http.responses = {
            "https://example.com": make_response(
                text="<html></html>",
                headers={"content-type": "text/html", "server": "nginx", "x-powered-by": "Express"}
            ),
        }

        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert result.fingerprint.headers.get("server") == "nginx"
        assert result.fingerprint.headers.get("x-powered-by") == "Express"

    @pytest.mark.asyncio
    async def test_fingerprint_collects_js_bundles(self, mock_http):
        """Fingerprint collects JavaScript bundle URLs."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><head><script src="/_next/static/chunks/main.js"></script></head></html>'
            ),
        }

        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert "https://example.com/_next/static/chunks/main.js" in result.fingerprint.js_bundles

    @pytest.mark.asyncio
    async def test_fingerprint_collects_api_endpoints(self, mock_http):
        """Fingerprint collects API endpoint URLs."""
        mock_http.responses = {
            "https://example.com": make_response(
                text='<html><body><a href="/api/users">Users</a><form action="/api/auth/login"></form></body></html>'
            ),
        }

        recon = Reconnaissance(target_url="https://example.com", max_depth=1, max_pages=5)
        result = await recon.run(mock_http)

        assert "https://example.com/api/users" in result.fingerprint.api_endpoints
        assert "https://example.com/api/auth/login" in result.fingerprint.api_endpoints