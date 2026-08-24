from vibeshield.config import settings
from vibeshield.models.recon import ReconData
from vibeshield.scanner.crawl import Crawler
from vibeshield.utils.http import HTTPClient


class Reconnaissance:
    def __init__(
        self,
        target_url: str,
        max_depth: int = settings.DEFAULT_MAX_DEPTH,
        max_pages: int = settings.DEFAULT_MAX_PAGES,
    ):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages

    async def run(self, http: HTTPClient) -> ReconData:
        crawler = Crawler(
            base_url=self.target_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
        )
        return await crawler.crawl(http)