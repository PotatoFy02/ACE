# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE - Automated Cybersecurity Engine
# Central environment variable validation. App refuses to start if vars missing.
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Pot (PotatoFy02). All rights reserved.
# ACE - Automated Cybersecurity Engine
# Central environment variable validation. App refuses to start if vars missing.
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# regardless of which directory the process is launched from.
_ENV_FILE = Path(__file__).parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

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


settings = Settings()  # type: ignore[call-arg]