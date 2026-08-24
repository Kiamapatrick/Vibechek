import asyncio
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from vibeshield.models.recon import CrawledPage, FingerprintResult, ReconData
from vibeshield.utils.http import HTTPClient
from vibeshield.utils.patterns import BAAS_PATTERNS, FRAMEWORK_PATTERNS


class Crawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        max_pages: int = 20,
        rate_limit: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.rate_limit = rate_limit
        self.visited: set[str] = set()
        self.queue: deque[tuple[str, int]] = deque()
        self.pages: list[CrawledPage] = []
        self._semaphore = asyncio.Semaphore(3)

    async def crawl(self, http: HTTPClient) -> ReconData:
        self.queue.append((self.base_url, 0))

        while self.queue and len(self.pages) < self.max_pages:
            url, depth = self.queue.popleft()
            if url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(url)
            page = await self._fetch_page(url, depth, http)
            if page:
                self.pages.append(page)
                if depth < self.max_depth:
                    self._extract_links(page)

        fingerprint = self._fingerprint()
        return ReconData(
            target_url=self.base_url,
            base_url=self.base_url,
            pages=self.pages,
            fingerprint=fingerprint,
        )

    async def _fetch_page(self, url: str, depth: int, http: HTTPClient) -> CrawledPage | None:
        async with self._semaphore:
            try:
                resp = await http.get(url)
                content_type = resp.headers.get("content-type", "")

                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    return None

                html = resp.text
                soup = BeautifulSoup(html, "lxml")

                links = []
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    normalized = self._normalize_url(href)
                    if normalized and self._is_same_origin(normalized):
                        links.append(normalized)

                scripts = []
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    normalized = self._normalize_url(src)
                    if normalized:
                        scripts.append(normalized)

                forms = []
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()
                    inputs = []
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inputs.append({
                            "name": inp.get("name"),
                            "type": inp.get("type"),
                            "required": inp.has_attr("required"),
                        })
                    forms.append({
                        "action": self._normalize_url(action) or url,
                        "method": method,
                        "inputs": inputs,
                    })

                return CrawledPage(
                    url=url,
                    depth=depth,
                    status_code=resp.status_code,
                    content_type=content_type,
                    html=html,
                    headers=dict(resp.headers),
                    links=links,
                    scripts=scripts,
                    forms=forms,
                )
            except Exception:
                return None

    def _normalize_url(self, url: str) -> str | None:
        if not url or url.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            return None
        try:
            absolute = urljoin(self.base_url, url)
            absolute, _ = urldefrag(absolute)
            return absolute
        except Exception:
            return None

    def _is_same_origin(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.parsed_base.netloc
        except Exception:
            return False

    def _extract_links(self, page: CrawledPage) -> None:
        for link in page.links:
            if link not in self.visited and link not in [q[0] for q in self.queue]:
                self.queue.append((link, page.depth + 1))

    def _fingerprint(self) -> FingerprintResult:
        all_html = "\n".join(p.html for p in self.pages)
        all_scripts = []
        for p in self.pages:
            all_scripts.extend(p.scripts)

        framework = None
        framework_version = None
        for name, pattern in FRAMEWORK_PATTERNS:
            if pattern.search(all_html):
                framework = name
                break

        baas = []
        for name, pattern in BAAS_PATTERNS:
            if pattern.search(all_html):
                baas.append(name)

        technologies = []
        if framework:
            technologies.append(framework)
        technologies.extend(baas)

        headers = {}
        if self.pages:
            headers = dict(self.pages[0].headers)

        api_endpoints = []
        for page in self.pages:
            for link in page.links:
                if any(p in link for p in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"]):
                    api_endpoints.append(link)
            for form in page.forms:
                action = form.get("action", "")
                if any(p in action for p in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/"]):
                    api_endpoints.append(action)

        js_bundles = list(set(all_scripts))

        return FingerprintResult(
            framework=framework,
            framework_version=framework_version,
            baas=baas,
            technologies=technologies,
            headers=headers,
            js_bundles=js_bundles,
            api_endpoints=list(set(api_endpoints)),
        )