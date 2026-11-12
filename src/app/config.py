from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Runtime connection. Points at the non-superuser app role
    # (shieldscan_app) once the RLS cutover happens; a superuser here bypasses
    # RLS unconditionally, which is the gap the cutover closes.
    DATABASE_URL: str
    # Owner connection (shieldscan), used ONLY by alembic and
    # scripts/verify_rls_verbose.py — both do DDL and CREATE ROLE, which the
    # app role cannot and must not be able to do. Falls back to DATABASE_URL
    # when unset so nothing breaks before the split is configured.
    MIGRATION_DATABASE_URL: str | None = None
    # App-role credentials, used by the test harness to connect its sessions
    # the same way production will. Kept separate from DATABASE_URL so the
    # suite exercises the enforced path before and after the cutover.
    APP_DB_USER: str = "shieldscan_app"
    APP_DB_PASSWORD: str | None = None
    # Kill-switch for the tenant guard ONLY (app/db/tenant_guard.py). Never
    # governs the after_begin re-apply or the pool reset handler: their
    # off-state was demonstrated to leak tenant context between requests,
    # which is strictly worse than the guard raising. Default ON; a disabled
    # guard logs at WARNING on every startup.
    TENANT_GUARD_ENABLED: bool = True
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
    # Root log level for the API process, applied by app.logging_config.
    # Until that module existed there was no logging configuration at all and
    # uvicorn configures only its own loggers, so every app-level INFO line
    # was discarded and warnings surfaced through logging.lastResort without
    # timestamp or logger name. INFO is the useful default: src/ has 15 INFO
    # call sites total.
    LOG_LEVEL: str = "INFO"
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

    # Public quick scans (M11 pre-work; ADDENDUM-CRITICAL-5 §2). Scans run
    # inside one system organization, created on first use by slug; results
    # are addressed by an emailed token and expire. Limits are per fixed
    # window (services.rate_limiter): one scan per email per day, five per
    # IP per hour (approved dashboard design v1.0, flow F1).
    PUBLIC_SCAN_ORG_SLUG: str = "shieldscan-public"
    PUBLIC_SCAN_EMAIL_DAILY_LIMIT: int = 1
    PUBLIC_SCAN_IP_HOURLY_LIMIT: int = 5
    PUBLIC_SCAN_RESULT_TTL_DAYS: int = 7
    PUBLIC_SCAN_VISIBLE_FINDINGS: int = 3
    # Base URL of the web app, for links in emails and public responses.
    APP_BASE_URL: str = "https://app.shieldscan.io"
    # M12 kill switch: False makes every plan cap and feature gate pass
    # (metering and the billing summary keep working). For incidents —
    # a bad catalog edit, a Redis outage that mis-resolves limits — and
    # for the test harness, where most orgs have no subscription row.
    PLAN_LIMITS_ENFORCED: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()  # type: ignore[call-arg]
