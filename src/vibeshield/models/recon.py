from dataclasses import dataclass, field

from vibeshield.models.report import FingerprintResult


@dataclass
class CrawledPage:
    url: str
    depth: int
    status_code: int
    content_type: str
    html: str
    headers: dict
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)


@dataclass
class ReconData:
    target_url: str
    base_url: str
    pages: list[CrawledPage] = field(default_factory=list)
    fingerprint: FingerprintResult = field(default_factory=FingerprintResult)
    errors: list[str] = field(default_factory=list)

    def get_all_html(self) -> str:
        return "\n".join(p.html for p in self.pages)

    def get_all_scripts(self) -> list[str]:
        scripts = []
        for p in self.pages:
            scripts.extend(p.scripts)
        return list(set(scripts))

    def get_all_forms(self) -> list[dict]:
        forms = []
        for p in self.pages:
            forms.extend(p.forms)
        return forms

    def get_api_endpoints(self) -> list[str]:
        return self.fingerprint.api_endpoints

    def get_js_bundles(self) -> list[str]:
        return self.fingerprint.js_bundles