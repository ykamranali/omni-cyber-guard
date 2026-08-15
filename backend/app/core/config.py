"""
Application configuration for Omni Cyber Guard.
Powered by Omni Digital Solution.
"""
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "Omni Cyber Guard"
    COMPANY_NAME: str = "Omni Digital Solution"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"

    SECRET_KEY: str = "insecure-dev-secret-change-me"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    DATABASE_URL: str = "postgresql://ocg_user:ocg_password@localhost:5432/omni_cyber_guard"
    REDIS_URL: str = "redis://localhost:6379/0"

    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    FIRST_SUPERADMIN_EMAIL: str = "admin@omnidigitalsolution.com"
    FIRST_SUPERADMIN_PASSWORD: str = "ChangeMe!12345"

    RATE_LIMIT_PER_MINUTE: int = 120


settings = Settings()
