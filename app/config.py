"""Application configuration.

Nothing secret lives in this file. Secrets are read from the environment, or
from a file (``<NAME>_FILE``) so a secrets manager can mount them as a volume
instead of exposing them as environment variables.
"""
import os
from pathlib import Path
from typing import Optional


def _read_setting(name: str, default: Optional[str] = None) -> Optional[str]:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default)


DATABASE_URL = _read_setting("DATABASE_URL", "sqlite:///./vulntracker.db")

# Fail closed: refuse to start without a strong signing key rather than
# falling back to a default that is public in the source repository.
SECRET_KEY = _read_setting("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY (or SECRET_KEY_FILE) must be set to a random value of at "
        "least 32 characters, e.g.: openssl rand -hex 32"
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")
# Bearer token the notification service requires on every call (optional here:
# if unset, no Authorization header is sent and the notify service will refuse).
NOTIFY_API_TOKEN = _read_setting("NOTIFY_API_TOKEN")

# Base URL used to build share links. Deliberately NOT derived from the
# request's Host header: that header is client-controlled, so using it would
# allow host-header injection into links we hand out.
SHARE_BASE_URL = os.environ.get("SHARE_BASE_URL", "http://localhost:8000").rstrip("/")

# Comma-separated list of origins allowed to call the API from a browser.
# Empty (the default) means no cross-origin access.
CORS_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()
]
