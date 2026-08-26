from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TriageSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    groq_api_key: str | None = Field(
        default=None,
        description=(
            "Groq API key for LLM calls. Optional here so GroqClient can be "
            "constructed with an explicit api_key= argument without needing "
            "GROQ_API_KEY set in the environment; GroqClient itself raises a "
            "clear error if neither source provides a key."
        ),
    )
    model: str = Field(default="openai/gpt-oss-20b", description="Groq model to use")
    temperature: float = Field(default=0.1, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: int = Field(default=2048, gt=0, description="Max tokens in response")
    max_retries: int = Field(default=3, ge=0, description="Max retry attempts for retryable Groq API errors")
    retry_base_delay: float = Field(default=1.0, gt=0, description="Base delay (seconds) for exponential backoff between retries")


_settings: TriageSettings | None = None


def get_settings() -> TriageSettings:
    global _settings
    if _settings is None:
        _settings = TriageSettings()
    return _settings