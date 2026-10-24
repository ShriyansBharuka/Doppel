"""Application configuration powered by pydantic-settings."""

from functools import lru_cache
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Doppel application settings loaded from environment or .env file."""

    DOPPEL_ENV: str = "dev"
    DOPPEL_SECRET: str = ""
    JWT_SECRET: str = ""
    STORAGE: str = "memory"
    MONGO_URI: str = ""
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    CORS_ORIGINS: str = "http://localhost:5173"
    SCENARIO_SEED: int = 42

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_secrets(self) -> "Settings":
        """Ensure secrets are present; in dev mode, provide fallback keys."""
        if self.DOPPEL_ENV == "dev":
            if not self.DOPPEL_SECRET:
                self.DOPPEL_SECRET = "dev-doppel-secret-key-32-chars-long"
            if not self.JWT_SECRET:
                self.JWT_SECRET = "dev-jwt-secret-key-32-chars-long"
        else:
            if not self.DOPPEL_SECRET:
                raise ValueError("DOPPEL_SECRET must be set in non-dev environment")
            if not self.JWT_SECRET:
                raise ValueError("JWT_SECRET must be set in non-dev environment")
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        """Return CORS origins parsed as a list of trimmed strings."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


@lru_cache()
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
