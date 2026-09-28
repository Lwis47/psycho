"""Local configuration template.

Copy this file to ``config.py`` for local development, then replace the
placeholder values. Production deployments should use EHH_* environment
variables instead.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = "replace-with-a-long-random-secret"
DATABASE_PATH = os.path.join(BASE_DIR, "instance", "ehh.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MAX_CONTENT_LENGTH = 100 * 1024 * 1024

MAIL_SERVER = ""
MAIL_PORT = 587
MAIL_USERNAME = ""
MAIL_PASSWORD = ""
MAIL_FROM = "Ethical Hacking Hub <noreply@example.com>"

ADMIN_EMAIL = "admin@ehh.local"
