"""
Application configuration for Omni Cyber Guard.
Powered by Omni Digital Solution.
"""
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that ship in .env.example and as in-code defaults. Booting with any of
# these while ENVIRONMENT=production is refused at startup — see
# Settings.assert_production_ready().
INSECURE_DEFAULTS = {
    "SECRET_KEY": "insecure-dev-secret-change-me",
    "FIRST_SUPERADMIN_PASSWORD": "ChangeMe!12345",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "Omni Cyber Guard"
    COMPANY_NAME: str = "Omni Digital Solution"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"

    SECRET_KEY: str = INSECURE_DEFAULTS["SECRET_KEY"]
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    DATABASE_URL: str = "postgresql://ocg_user:ocg_password@localhost:5432/omni_cyber_guard"
    REDIS_URL: str = "redis://localhost:6379/0"

    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # PostgreSQL row-level security, enforcing tenant isolation independently
    # of application query filters. See app/db/tenancy.py.
    ENABLE_ROW_LEVEL_SECURITY: bool = True

    # Fernet key protecting stored scan credentials. Deliberately separate from
    # SECRET_KEY: rotating session signing must not make the vault unreadable.
    # Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    CREDENTIAL_ENCRYPTION_KEY: str = ""

    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    FIRST_SUPERADMIN_EMAIL: str = "admin@omnidigitalsolution.com"
    FIRST_SUPERADMIN_PASSWORD: str = INSECURE_DEFAULTS["FIRST_SUPERADMIN_PASSWORD"]

    # Requests per minute, per client address, across the API.
    RATE_LIMIT_PER_MINUTE: int = 120
    # Tighter budget for the credential-accepting endpoints.
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 10
    # Only enable behind a reverse proxy you control; otherwise a client can
    # forge X-Forwarded-For and evade rate limiting.
    TRUST_PROXY_HEADERS: bool = False

    # Passive packet monitoring needs CAP_NET_RAW and is only meaningful where
    # the process can see the segment it is meant to observe.
    ENABLE_PASSIVE_MONITOR: bool = True

    # --- Vulnerability intelligence -----------------------------------
    # Optional NVD API key. Without one NVD allows 5 requests per 30 seconds;
    # with one, 50. Free from https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY: str = ""
    # How far back the first NVD sync reaches. The full catalogue is ~280,000
    # CVEs and would take hours unkeyed, so the first run is bounded and says
    # so rather than appearing complete.
    NVD_INITIAL_SYNC_DAYS: int = 120
    # Automatic daily synchronisation of the KEV, EPSS and NVD feeds.
    ENABLE_INTEL_SYNC: bool = True

    OVERRIDE_LOCAL_IP: str | None = None

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.strip().lower() in ("production", "prod")

    def insecure_defaults_in_use(self) -> list[str]:
        return [
            name for name, insecure in INSECURE_DEFAULTS.items()
            if getattr(self, name) == insecure
        ]

    def assert_production_ready(self) -> None:
        """Refuse to start a production deployment on shipped default secrets."""
        if not self.is_production:
            return

        problems = [
            f"{name} is still set to its shipped default value"
            for name in self.insecure_defaults_in_use()
        ]

        if not self.CREDENTIAL_ENCRYPTION_KEY.strip():
            problems.append(
                "CREDENTIAL_ENCRYPTION_KEY is not set, so stored scan credentials "
                "would be encrypted with a key derived from SECRET_KEY"
            )

        if not self.ENABLE_ROW_LEVEL_SECURITY:
            problems.append(
                "ENABLE_ROW_LEVEL_SECURITY is off, leaving tenant isolation "
                "dependent on application query filters alone"
            )

        if problems:
            raise RuntimeError(
                "Refusing to start in production:\n  - " + "\n  - ".join(problems)
            )


settings = Settings()
