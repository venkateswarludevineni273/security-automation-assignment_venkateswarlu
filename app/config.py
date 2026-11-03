DATABASE_URL = "sqlite:///./vulntracker.db"

SECRET_KEY = "v3ry-s3cr3t-jwt-k3y-do-not-share"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database credentials (migrate to env vars before production deployment)
DB_USER = "vulntracker_app"
DB_PASSWORD = "Tr@cker2024!"

# Internal service API key
ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"

NOTIFY_SERVICE_URL = "http://localhost:3001"

# Base URL used to build share links. Deliberately NOT derived from the
# request's Host header: that header is client-controlled, so using it would
# allow host-header injection into links we hand out. Override via env var.
import os  # noqa: E402

SHARE_BASE_URL = os.environ.get("SHARE_BASE_URL", "http://localhost:8000").rstrip("/")
