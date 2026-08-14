from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    QDRANT_URL: str
    ANTHROPIC_API_KEY: str
    OPENAI_API_KEY: str
    STRIPE_SECRET_KEY: str
    STRIPE_WEBHOOK_SECRET: str
    R2_ACCOUNT_ID: str
    R2_ACCESS_KEY: str
    R2_SECRET_KEY: str
    R2_BUCKET: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    FERNET_KEY: str
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "https://app.shieldscan.io"]
    ENVIRONMENT: str = "development"
    # Hard cap on a single mobile-upload (.apk / .ipa) body size, in MB.
    # Enforced at the route handler before the body is read (via
    # Content-Length pre-check) and again after read for clients that
    # don't send Content-Length. Task 3.3.
    MOBILE_UPLOAD_HARD_LIMIT_MB: int = 500
    # Tool plugin ids (raw_findings.tool_metadata->>'plugin_id') that must never
    # be promoted to a Vulnerability. Comma-separated; blank disables the filter.
    #
    # Config, not a code constant, because the list grows per target type — a
    # SPA advisory that is noise for one target may be worth surfacing for
    # another, and that call shouldn't need a release. Applied at PROMOTION
    # only: raw_findings is the 90-day audit record (SPEC §5.4) and stays
    # complete regardless of this setting.
    #
    # Default: ZAP 10109 "Modern Web Application" — an informational advisory
    # that the target is a SPA, not a finding (74 raw findings on one live scan).
    PROMOTION_DENYLIST_PLUGIN_IDS: str = "10109"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()  # type: ignore[call-arg]
