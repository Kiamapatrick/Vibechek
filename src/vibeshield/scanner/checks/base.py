from abc import ABC, abstractmethod

from vibeshield.models.finding import Finding
from vibeshield.models.recon import ReconData
from vibeshield.utils.http import HTTPClient


class BaseCheck(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, recon: ReconData, http: HTTPClient) -> list[Finding]:
        pass