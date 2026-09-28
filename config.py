import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ---------------------------------------------------------------------------
# General
# ----------------------------------------------
SECRET_KEY = os.environ.get("EHH_SECRET_KEY", "dev-secret-change-me")
DATABASE_PATH = os.path.join(BASE_DIR, "instance", "ehh.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload

# ---------------------------------------------------------------------------
# Email / SMTP
MAIL_SERVER = os.environ.get("EHH_MAIL_SERVER", "")
MAIL_PORT = int(os.environ.get("EHH_MAIL_PORT", "587"))
MAIL_USERNAME = os.environ.get("EHH_MAIL_USERNAME", "")
MAIL_PASSWORD = os.environ.get("EHH_MAIL_PASSWORD", "")
MAIL_FROM = os.environ.get("EHH_MAIL_FROM", "Ethical Hacking Hub <noreply@example.com>")

EMAIL_CONFIGURED = bool(MAIL_SERVER and MAIL_USERNAME and MAIL_PASSWORD)

# ---------------------------------------------------------------------------
# Admin bootstrap
# ---------------------------------------------------------------------------
# The first account created with this email is automatically made an admin.
ADMIN_EMAIL = os.environ.get("EHH_ADMIN_EMAIL", "admin@ehh.local")
