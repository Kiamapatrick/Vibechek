from dataclasses import dataclass

from vibeshield.models.finding import Finding


@dataclass
class ContextSnippet:
    topic: str
    content: str
    source_file: str


@dataclass
class TriageResult:
    finding: Finding
    explanation: str
    exploitability: int
    fix: str
    revised_priority: int
    source: str = "llm"
    prompt_version: str = "v1"

    def __post_init__(self) -> None:
        if not 1 <= self.exploitability <= 5:
            raise ValueError("exploitability must be between 1 and 5")
        if not 1 <= self.revised_priority <= 5:
            raise ValueError("revised_priority must be between 1 and 5")
        if self.source not in ("llm", "baseline"):
            raise ValueError("source must be 'llm' or 'baseline'")