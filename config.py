from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "mcp-gateway"
    debug: bool = False

    otl_exporter_url: str = "http://localhost:4317"
    frontend_url: str = "http://localhost:5173"
    host: str = "http://localhost:8000"
    # database_url: str


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
