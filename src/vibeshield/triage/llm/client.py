import json
from typing import Any

from groq import Groq

from vibeshield.models.finding import Finding
from vibeshield.triage.config import get_settings
from vibeshield.triage.llm.prompts.prompt_v1 import PROMPT_V1
from vibeshield.triage.models import ContextSnippet, TriageResult


class GroqClient:
    """Groq API client for structured triage generation."""
    
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> None:
        settings = get_settings()
        self._client = Groq(api_key=api_key or settings.groq_api_key)
        self._model = model or settings.model
        self._temperature = temperature if temperature is not None else settings.temperature
        self._max_tokens = max_tokens or settings.max_tokens
        self._prompt_template = PROMPT_V1
    
    def generate(
        self,
        finding: Finding,
        context: list[ContextSnippet],
        prompt_version: str = "v1",
    ) -> TriageResult:
        """Generate a triage result for a finding using Groq structured output."""
        if prompt_version != "v1":
            raise ValueError(f"Unknown prompt version: {prompt_version}")
        
        prompt = self._prompt_template.build(finding, context)
        
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": self._prompt_template.system},
                {"role": "user", "content": prompt},
            ],
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            response_format={"type": "json_object"},
        )
        
        content = response.choices[0].message.content
        if content is None:
            raise ValueError("Empty response from Groq")
        
        data = json.loads(content)
        return self._parse_triage_result(data, finding, prompt_version)
    
    def _parse_triage_result(
        self,
        data: dict[str, Any],
        finding: Finding,
        prompt_version: str,
    ) -> TriageResult:
        """Parse and validate Groq JSON response into TriageResult."""
        required_fields = ["explanation", "exploitability", "fix", "revised_priority"]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field in LLM response: {field}")
        
        return TriageResult(
            finding=finding,
            explanation=data["explanation"],
            exploitability=int(data["exploitability"]),
            fix=data["fix"],
            revised_priority=int(data["revised_priority"]),
            source="llm",
            prompt_version=prompt_version,
        )


# Module-level singleton
_client: GroqClient | None = None


def get_client() -> GroqClient:
    """Get or create the global GroqClient instance."""
    global _client
    if _client is None:
        _client = GroqClient()
    return _client