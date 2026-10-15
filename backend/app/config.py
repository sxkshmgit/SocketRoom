from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Always load backend/.env, regardless of the working directory.
# DATABASE_URL is left untouched so the SQLite path behaves exactly as before.
ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ENV_FILE, extra="ignore")

    app_name: str = "SocketRoom"
    debug: bool = False
    database_url: str = "sqlite:///./socketroom.db"

    # Required: no default, so the app refuses to start without it.
    secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=60, gt=0)

    @field_validator("secret_key")
    @classmethod
    def reject_placeholder(cls, value: str) -> str:
        if value.lower().startswith("change-me"):
            raise ValueError("SECRET_KEY must be replaced with a real random secret")
        return value


settings = Settings()