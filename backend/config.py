
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "vibeshield"
    MONGODB_MAX_RETRIES: int = 3
    MONGODB_RETRY_BASE_DELAY: float = 0.5
    MONGODB_MAX_POOL_SIZE: int = 10
    MONGODB_MIN_POOL_SIZE: int = 1
    MONGODB_SERVER_SELECTION_TIMEOUT_MS: int = 5000
    MONGODB_CONNECT_TIMEOUT_MS: int = 10000
    MONGODB_SOCKET_TIMEOUT_MS: int = 20000
    MONGODB_FAILURE_COOLDOWN_SECONDS: float = 5.0
    
    # Groq LLM
    GROQ_API_KEY: str | None = None
    GROQ_MODEL: str = "llama-3.1-70b-versatile"
    GROQ_MAX_RETRIES: int = 3
    GROQ_TIMEOUT: float = 30.0

    # Scanner defaults
    DEFAULT_TIMEOUT: float = 10.0
    DEFAULT_MAX_PAGES: int = 20
    DEFAULT_MAX_DEPTH: int = 2

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()