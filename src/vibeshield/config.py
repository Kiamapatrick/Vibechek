from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    VERSION: str = "0.1.0"
    DEFAULT_TIMEOUT: float = 10.0
    DEFAULT_MAX_PAGES: int = 20
    DEFAULT_MAX_DEPTH: int = 2
    DEFAULT_MAX_REDIRECTS: int = 5
    CRAWL_RATE_LIMIT: float = 10.0
    HTTP_RETRIES: int = 3
    CONFIDENCE_THRESHOLD: float = 0.5
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    OSV_BATCH_API_URL: str = "https://api.osv.dev/v1/querybatch"


settings = Settings()