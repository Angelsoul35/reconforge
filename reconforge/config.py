"""Application configuration, loaded from environment variables (prefix ``RF_``)."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RF_", env_file=".env", extra="ignore")

    environment: str = "local"
    # A safety switch: real (network) collectors must opt in explicitly. The
    # bundled collectors are offline regardless; this documents the intent.
    allow_active_scan: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
