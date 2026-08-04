# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE - Automated Cybersecurity Engine
# Central environment variable validation. App refuses to start if vars missing.
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    supabase_url: str
    supabase_anon_key: str
    supabase_service_key: str = ""
    supabase_jwt_secret: str = ""
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.6-flash"
    gemini_timeout_ms: int = 45000
    daily_generation_cap: int = 500
    sentry_dsn: str = ""
    github_token: str = ""
    slack_webhook_url: str = ""
    slack_bot_token: str = ""
    slack_alert_channel: str = "#security-alerts"
    slack_signing_secret: str = ""
    ace_base_url: str = "https://ace-i9mz.onrender.com"
    free_project_limit: int = 10
    allowed_origins: str = "http://localhost:8000"
    render_git_branch: str = "local"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


settings = Settings()  # type: ignore[call-arg]