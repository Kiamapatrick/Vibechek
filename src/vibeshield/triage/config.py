from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class TriageSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    groq_api_key: str = Field(..., description="Groq API key for LLM calls")
    model: str = Field(default="llama-3.3-70b-versatile", description="Groq model to use")
    temperature: float = Field(default=0.1, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: int = Field(default=2048, gt=0, description="Max tokens in response")


_settings: TriageSettings | None = None


def get_settings() -> TriageSettings:
    global _settings
    if _settings is None:
        _settings = TriageSettings()
    return _settings