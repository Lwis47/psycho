"""Runtime configuration for local development and hosted deployments.

Production settings come from environment variables.  For local development,
an untracked ``config.py`` can override the documented defaults.
"""

import os
from pathlib import Path

try:
    import config as _local_config
except ModuleNotFoundError:
    _local_config = None


BASE_DIR = Path(__file__).resolve().parent


def _setting(name, default=None):
    """Read EHH_<name> from the environment, then local config.py, then default."""
    value = os.getenv(f"EHH_{name}")
    if value is not None:
        return value
    if _local_config is not None:
        return getattr(_local_config, name, default)
    return default


SECRET_KEY = _setting("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "EHH_SECRET_KEY must be set in the environment or in an untracked config.py file."
    )

DATABASE_PATH = _setting("DATABASE_PATH", str(BASE_DIR / "instance" / "ehh.db"))
UPLOAD_FOLDER = _setting("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
AVATAR_FOLDER = _setting("AVATAR_FOLDER", str(BASE_DIR / "static" / "avatars"))
MAX_CONTENT_LENGTH = int(_setting("MAX_CONTENT_LENGTH", 25 * 1024 * 1024))

MAIL_SERVER = _setting("MAIL_SERVER", "")
MAIL_PORT = int(_setting("MAIL_PORT", 587))
MAIL_USERNAME = _setting("MAIL_USERNAME", "")
MAIL_PASSWORD = _setting("MAIL_PASSWORD", "")
MAIL_FROM = _setting("MAIL_FROM", MAIL_USERNAME)
EMAIL_CONFIGURED = all((MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM))
CONSOLE_EMAIL_ENABLED = str(
    _setting("CONSOLE_EMAIL_ENABLED", "false" if os.getenv("RENDER") else "true")
).lower() in {"1", "true", "yes", "on"}

ADMIN_EMAIL = _setting("ADMIN_EMAIL", "")
