from abc import ABC, abstractmethod

from vibeshield.models.finding import Finding
from vibeshield.models.recon import ReconData
from vibeshield.utils.http import HTTPClient


class BaseCheck(ABC):
    name: str = ""
    description: str = ""
    wstg_id: str = ""
    attck_ids: list[str] = []

    @abstractmethod
    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        pass

    def get_tags(self) -> tuple[str, list[str]]:
        return self.wstg_id, self.attck_ids