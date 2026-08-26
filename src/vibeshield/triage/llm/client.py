import json
from typing import Any

from groq import APIConnectionError, APITimeoutError, Groq, RateLimitError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from vibeshield.models.finding import Finding
from vibeshield.triage.config import get_settings
from vibeshield.triage.llm.prompts.prompt_v1 import PROMPT_V1
from vibeshield.triage.models import ContextSnippet, TriageResult

# Errors worth retrying: transient/rate-limit conditions where a retry is
# likely to succeed. Deliberately excludes the broader APIError (e.g. bad
# request, auth failure) which should fail fast instead of retrying.
_RETRYABLE_ERRORS = (RateLimitError, APITimeoutError, APIConnectionError)


class GroqClient:
    """Groq API client for structured triage generation."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        max_retries: int | None = None,
        retry_base_delay: float | None = None,
    ) -> None:
        settings = get_settings()

        resolved_key = api_key or settings.groq_api_key
        if not resolved_key:
            raise ValueError(
                "No Groq API key provided. Set GROQ_API_KEY in the environment/.env, "
                "or pass GroqClient(api_key=...) explicitly."
            )

        self._client = Groq(api_key=resolved_key)
        self._model = model or settings.model
        self._temperature = temperature if temperature is not None else settings.temperature
        self._max_tokens = max_tokens or settings.max_tokens
        self._max_retries = max_retries if max_retries is not None else settings.max_retries
        self._retry_base_delay = retry_base_delay if retry_base_delay is not None else settings.retry_base_delay
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

        response = self._call_with_retry(prompt)

        content = response.choices[0].message.content
        if content is None:
            raise ValueError("Empty response from Groq")

        data = json.loads(content)
        return self._parse_triage_result(data, finding, prompt_version)

    def _call_with_retry(self, prompt: str) -> Any:
        """Call the Groq chat completion API, retrying on transient errors
        (rate limits, timeouts, connection errors) with exponential backoff.
        Retry behavior is configurable via max_retries / retry_base_delay."""

        @retry(
            retry=retry_if_exception_type(_RETRYABLE_ERRORS),
            stop=stop_after_attempt(self._max_retries + 1),  # +1: first attempt isn't a "retry"
            wait=wait_exponential(multiplier=self._retry_base_delay),
            reraise=True,
        )
        def _call() -> Any:
            return self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": self._prompt_template.system},
                    {"role": "user", "content": prompt},
                ],
                temperature=self._temperature,
                max_tokens=self._max_tokens,
                response_format={"type": "json_object"},
            )

        return _call()
    
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