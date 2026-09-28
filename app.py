import os
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from collections import defaultdict
import time

import settings as config
from db import get_db, init_db
from mailer import send_verification_code, send_reset_code

app = Flask(__name__)
app.config.from_object(config)
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("EHH_HTTPS_ONLY", "0").lower() in {"1", "true", "yes"}
init_db(app)

ALLOWED_EXTENSIONS = {"pdf", "zip", "txt", "md", "pptx", "docx", "png", "jpg", "jpeg", "mp4", "iso_link"}
ALLOWED_AVATAR_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

LEARNING_PATHS = [
    {
        "slug": "network-security",
        "title": "Network Security",
        "description": "Learn how networks are attacked and defended: packet analysis, firewalls, VPNs and intrusion detection.",
        "icon": "network",
    },
    {
        "slug": "web-exploitation",
        "title": "Web Exploitation",
        "description": "SQL injection, XSS, CSRF, and authentication flaws — how web apps break and how to secure them.",
        "icon": "web",
    },
    {
        "slug": "penetration-testing",
        "title": "Penetration Testing",
        "description": "Structured methodology for authorized security assessments, from recon to reporting.",
        "icon": "pentest",
    },
    {
        "slug": "malware-analysis",
        "title": "Malware Analysis",
        "description": "Static and dynamic analysis techniques to understand what malicious software actually does.",
        "icon": "malware",
    },
    {
        "slug": "digital-forensics",
        "title": "Digital Forensics",
        "description": "Evidence collection, disk and memory analysis, and building a defensible chain of custody.",
        "icon": "forensics",
    },
    {
        "slug": "cryptography",
        "title": "Cryptography",
        "description": "The math and mechanics behind encryption, hashing, and the ways both get broken.",
        "icon": "crypto",
    },
    {
        "slug": "programming",
        "title": "Programming for Security",
        "description": "Build Python, scripting, and software fundamentals for security automation and secure tools.",
        "icon": "code",
    },
    {
        "slug": "nmap-network-scanning",
        "title": "Nmap & Network Scanning",
        "description": "Learn host discovery, port scanning, service detection, and scan interpretation in authorized labs.",
        "icon": "nmap",
    },
    {
        "slug": "linux-command-line",
        "title": "Linux & Command Line",
        "description": "Practice Linux fundamentals, shell workflows, permissions, processes, and essential security tooling.",
        "icon": "linux",
    },
    {
        "slug": "osint",
        "title": "OSINT & Digital Research",
        "description": "Use ethical open-source research methods to assess public information and document findings responsibly.",
        "icon": "osint",
    },
    {
        "slug": "cloud-security",
        "title": "Cloud Security",
        "description": "Understand cloud identity, access control, network exposure, storage security, and defensive monitoring.",
        "icon": "cloud",
    },
    {
        "slug": "incident-response",
        "title": "Incident Response",
        "description": "Learn alert triage, containment, investigation, recovery, and clear incident documentation.",
        "icon": "incident",
    },
]

LINUX_DISTROS = [
    {"name": "Kali Linux", "use": "Penetration testing & security auditing", "url": "https://www.kali.org/get-kali/"},
    {"name": "Parrot OS", "use": "Security, privacy & development", "url": "https://parrotsec.org/download/"},
    {"name": "BlackArch", "use": "Arch-based pentesting distro, 2800+ tools", "url": "https://blackarch.org/downloads.html"},
    {"name": "Ubuntu", "use": "General purpose, beginner friendly", "url": "https://ubuntu.com/download/desktop"},
    {"name": "Debian", "use": "Stable, general purpose base distro", "url": "https://www.debian.org/distrib/"},
    {"name": "Tails", "use": "Amnesic, privacy-focused live OS", "url": "https://tails.net/install/"},
    {"name": "Qubes OS", "use": "Security through compartmentalization", "url": "https://www.qubes-os.org/downloads/"},
    {"name": "ArchStrike", "use": "Arch-based, security & research", "url": "https://archstrike.org/download"},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def gen_code(length=6):
    return "".join(secrets.choice(string.digits) for _ in range(length))


def now():
    return datetime.utcnow()


def parse_dt(s):
    if not s:
        return None
    return datetime.fromisoformat(s)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if not user or not user["is_active"]:
            session.clear()
            flash("This account has been deactivated. Contact an administrator.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if not user or not user["is_active"]:
            session.clear()
            flash("This account has been deactivated. Contact an administrator.", "error")
            return redirect(url_for("login"))
        if not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def get_user_by_id(user_id):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_email(email):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


# ---------------------------------------------------------------------------
# Simple in-memory rate limiting (per IP + route). Good enough for a single
# dev-server process; swap for Flask-Limiter + Redis if you ever run this
# behind multiple worker processes in production.
# ---------------------------------------------------------------------------
_rate_limit_hits = defaultdict(list)


def rate_limit(max_attempts, window_seconds):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            key = f"{request.remote_addr}:{view.__name__}"
            now_ts = time.time()
            hits = _rate_limit_hits[key]
            hits[:] = [t for t in hits if now_ts - t < window_seconds]
            if len(hits) >= max_attempts:
                flash("Too many attempts. Please wait a minute and try again.", "error")
                return redirect(request.referrer or url_for("index"))
            hits.append(now_ts)
            return view(*args, **kwargs)
        return wrapped
    return decorator

# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html", paths=LEARNING_PATHS)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/developer")
def developer():
    return render_template("developer.html")


# ---------------------------------------------------------------------------
# Sign up + email verification
# ---------------------------------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
@rate_limit(max_attempts=10, window_seconds=60)
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not email or "@" not in email:
            flash("Enter a valid email address.", "error")
            return render_template("signup.html", email=email, full_name=full_name)

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("signup.html", email=email, full_name=full_name)

        if password != confirm:
            flash("Passwords don't match.", "error")
            return render_template("signup.html", email=email, full_name=full_name)

        db = get_db()
        existing = get_user_by_email(email)

        code = gen_code()
        expires = (now() + timedelta(minutes=15)).isoformat()
        password_hash = generate_password_hash(password)
        admin_email = (config.ADMIN_EMAIL or "").strip().lower()
        is_admin = 1 if email == admin_email else 0

        if existing:
            if existing["is_verified"]:
                flash("An account with that email already exists. Try logging in.", "error")
                return render_template("signup.html", email=email, full_name=full_name)
            # Re-signup before verifying: refresh the code/password/name.
            db.execute(
                """UPDATE users SET password_hash=?, full_name=?, verification_code=?, verification_expires=?
                   WHERE email=?""",
                (password_hash, full_name, code, expires, email),
            )
        else:
            db.execute(
                """INSERT INTO users (email, password_hash, full_name, is_admin, verification_code, verification_expires)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (email, password_hash, full_name, is_admin, code, expires),
            )
        db.commit()

        sent = send_verification_code(email, code)
        if not sent and not config.CONSOLE_EMAIL_ENABLED:
            flash("Email delivery is unavailable. Please contact the site administrator.", "error")
            return render_template("signup.html", email=email, full_name=full_name)
        session["pending_email"] = email
        flash("We sent a verification code to your email.", "success")
        return redirect(url_for("verify"))

    return render_template("signup.html", email="", full_name="")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("pending_email", "")

    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        code = request.form.get("code", "").strip()

        user = get_user_by_email(email)
        if not user:
            flash("No pending signup found for that email.", "error")
            return render_template("verify.html", email=email)

        if user["is_verified"]:
            flash("This account is already verified. Log in.", "success")
            return redirect(url_for("login"))

        expires = parse_dt(user["verification_expires"])
        if not expires or now() > expires:
            flash("That code expired. Request a new one below.", "error")
            return render_template("verify.html", email=email)

        if code != user["verification_code"]:
            flash("Incorrect code. Please try again.", "error")
            return render_template("verify.html", email=email)

        db = get_db()
        db.execute(
            "UPDATE users SET is_verified=1, verification_code=NULL, verification_expires=NULL WHERE email=?",
            (email,),
        )
        db.commit()
        session.pop("pending_email", None)
        flash("Email verified! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("verify.html", email=email)


@app.route("/resend-code", methods=["POST"])
@rate_limit(max_attempts=5, window_seconds=60)
def resend_code():
    email = request.form.get("email", "").lower().strip()
    user = get_user_by_email(email)
    if user and not user["is_verified"]:
        code = gen_code()
        expires = (now() + timedelta(minutes=15)).isoformat()
        db = get_db()
        db.execute(
            "UPDATE users SET verification_code=?, verification_expires=? WHERE email=?",
            (code, expires, email),
        )
        db.commit()
        sent = send_verification_code(email, code)
        if not sent and not config.CONSOLE_EMAIL_ENABLED:
            flash("Email delivery is unavailable. Please contact the site administrator.", "error")
            return redirect(url_for("verify", email=email))
    # Always show the same message so we don't leak which emails exist.
    flash("If that account is pending verification, a new code has been sent.", "success")
    return redirect(url_for("verify", email=email))


# ---------------------------------------------------------------------------
# Log in / log out
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@rate_limit(max_attempts=10, window_seconds=60)
def login():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "")

        user = get_user_by_email(email)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Incorrect email or password.", "error")
            return render_template("login.html", email=email)
        if not user["is_active"]:
            flash("This account has been deactivated. Contact an administrator.", "error")
            return render_template("login.html", email=email)

        if not user["is_verified"]:
            session["pending_email"] = email
            flash("Please verify your email before logging in.", "error")
            return redirect(url_for("verify"))

        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["is_admin"] = bool(user["is_admin"])
        session["theme"] = user["theme"]
        flash("Welcome back!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", email="")


@app.route("/logout")
def logout():
    session.clear()
    flash("You've been logged out.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Forgot / reset password
# ---------------------------------------------------------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
@rate_limit(max_attempts=5, window_seconds=60)
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        user = get_user_by_email(email)
        if user:
            code = gen_code()
            expires = (now() + timedelta(minutes=15)).isoformat()
            db = get_db()
            db.execute(
                "UPDATE users SET reset_token=?, reset_expires=? WHERE email=?",
                (code, expires, email),
            )
            db.commit()
            sent = send_reset_code(email, code)
            if not sent and not config.CONSOLE_EMAIL_ENABLED:
                flash("Email delivery is unavailable. Please contact the site administrator.", "error")
                return redirect(url_for("forgot_password"))
        # Same message whether or not the email exists in E.H.H.
        flash("If that email is registered with E.H.H., a reset code has been sent.", "success")
        return redirect(url_for("reset_password", email=email))

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = request.values.get("email", "").lower().strip()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        new_password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        user = get_user_by_email(email)
        if not user or not user["reset_token"]:
            flash("Invalid or expired reset request.", "error")
            return render_template("reset_password.html", email=email)

        expires = parse_dt(user["reset_expires"])
        if not expires or now() > expires:
            flash("That reset code expired. Request a new one.", "error")
            return render_template("reset_password.html", email=email)

        if code != user["reset_token"]:
            flash("Incorrect reset code.", "error")
            return render_template("reset_password.html", email=email)

        if len(new_password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", email=email)

        if new_password != confirm:
            flash("Passwords don't match.", "error")
            return render_template("reset_password.html", email=email)

        db = get_db()
        db.execute(
            "UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE email=?",
            (generate_password_hash(new_password), email),
        )
        db.commit()
        flash("Password reset. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", email=email)


# ---------------------------------------------------------------------------
# Dashboard + learning content
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Dashboard + learning content
# ---------------------------------------------------------------------------
# This SELECT is reused everywhere materials are listed: it attaches like/
# dislike counts, the current user's own reaction, and a comment count to
# each material row, so templates can render the action bar without extra
# queries per row.
MATERIALS_WITH_STATS_SQL = """
    SELECT
        m.*,
        (SELECT COUNT(*) FROM material_reactions r
            WHERE r.material_id = m.id AND r.reaction = 'like')    AS likes,
        (SELECT COUNT(*) FROM material_reactions r
            WHERE r.material_id = m.id AND r.reaction = 'dislike') AS dislikes,
        (SELECT COUNT(*) FROM material_comments c
            WHERE c.material_id = m.id)                            AS comment_count,
        (SELECT reaction FROM material_reactions r2
            WHERE r2.material_id = m.id AND r2.user_id = ?)        AS user_reaction
    FROM materials m
"""


def get_material_or_404(material_id):
    db = get_db()
    material = db.execute(
        MATERIALS_WITH_STATS_SQL + " WHERE m.id = ?",
        (session.get("user_id"), material_id),
    ).fetchone()
    if not material:
        abort(404)
    return material


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    materials = db.execute(
        MATERIALS_WITH_STATS_SQL + " ORDER BY m.uploaded_at DESC LIMIT 6",
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "dashboard.html", paths=LEARNING_PATHS, recent_materials=materials
    )


SORT_OPTIONS = {
    "newest": "m.uploaded_at DESC",
    "oldest": "m.uploaded_at ASC",
    "most_liked": "likes DESC, m.uploaded_at DESC",
    "most_commented": "comment_count DESC, m.uploaded_at DESC",
    "title": "m.title COLLATE NOCASE ASC",
}


@app.route("/dashboard/path/<slug>")
@login_required
def path_detail(slug):
    path = next((p for p in LEARNING_PATHS if p["slug"] == slug), None)
    if not path:
        abort(404)

    search = request.args.get("q", "").strip()
    sort = request.args.get("sort", "newest")
    if sort not in SORT_OPTIONS:
        sort = "newest"

    db = get_db()
    query = MATERIALS_WITH_STATS_SQL + " WHERE m.section = ?"
    params = [session["user_id"], slug]

    if search:
        query += " AND (m.title LIKE ? OR m.description LIKE ?)"
        like_term = f"%{search}%"
        params += [like_term, like_term]

    # SORT_OPTIONS keys are a fixed whitelist above, never user input directly,
    # so this is safe to interpolate rather than parameterize.
    query += f" ORDER BY {SORT_OPTIONS[sort]}"

    materials = db.execute(query, params).fetchall()
    return render_template(
        "path_detail.html", path=path, materials=materials, search=search, sort=sort
    )

@app.route("/materials/<int:material_id>")
@login_required
def material_detail(material_id):
    material = get_material_or_404(material_id)
    db = get_db()
    comments = db.execute(
        """SELECT c.*, u.email AS user_email
           FROM material_comments c
           JOIN users u ON u.id = c.user_id
           WHERE c.material_id = ?
           ORDER BY c.created_at ASC""",
        (material_id,),
    ).fetchall()
    return render_template("material_detail.html", material=material, comments=comments)


@app.route("/materials/<int:material_id>/view")
@login_required
def view_material(material_id):
    material = get_material_or_404(material_id)
    # as_attachment=False asks the browser to display the file inline
    # (PDFs open in-tab, images render directly) instead of forcing a save.
    return send_from_directory(
        config.UPLOAD_FOLDER, material["filename"], as_attachment=False
    )


@app.route("/materials/<int:material_id>/download")
@login_required
def download_material(material_id):
    material = get_material_or_404(material_id)
    return send_from_directory(
        config.UPLOAD_FOLDER, material["filename"],
        as_attachment=True, download_name=material["original_filename"]
    )


@app.route("/materials/<int:material_id>/react", methods=["POST"])
@login_required
def react_material(material_id):
    get_material_or_404(material_id)
    reaction = request.form.get("reaction")
    if reaction not in ("like", "dislike"):
        abort(400)

    db = get_db()
    existing = db.execute(
        "SELECT reaction FROM material_reactions WHERE material_id=? AND user_id=?",
        (material_id, session["user_id"]),
    ).fetchone()

    if existing and existing["reaction"] == reaction:
        # Clicking the same button again removes your reaction (toggle off).
        db.execute(
            "DELETE FROM material_reactions WHERE material_id=? AND user_id=?",
            (material_id, session["user_id"]),
        )
    elif existing:
        # Switching from like -> dislike or vice versa.
        db.execute(
            "UPDATE material_reactions SET reaction=?, created_at=datetime('now') "
            "WHERE material_id=? AND user_id=?",
            (reaction, material_id, session["user_id"]),
        )
    else:
        db.execute(
            "INSERT INTO material_reactions (material_id, user_id, reaction) VALUES (?, ?, ?)",
            (material_id, session["user_id"], reaction),
        )
    db.commit()

    next_url = request.form.get("next") or url_for("material_detail", material_id=material_id)
    return redirect(next_url)


@app.route("/materials/<int:material_id>/comment", methods=["POST"])
@login_required
def comment_material(material_id):
    get_material_or_404(material_id)
    body = request.form.get("body", "").strip()
    if not body:
        flash("Comment can't be empty.", "error")
    else:
        db = get_db()
        db.execute(
            "INSERT INTO material_comments (material_id, user_id, body) VALUES (?, ?, ?)",
            (material_id, session["user_id"], body),
        )
        db.commit()
    return redirect(url_for("material_detail", material_id=material_id))


@app.route("/linux-distros")
@login_required
def linux_distros():
    return render_template("linux_distros.html", distros=LINUX_DISTROS)


# ---------------------------------------------------------------------------
# Admin: upload learning materials
# ---------------------------------------------------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_panel():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        section = request.form.get("section", "")
        description = request.form.get("description", "").strip()
        file = request.files.get("file")

        valid_sections = {p["slug"] for p in LEARNING_PATHS}
        if not title or section not in valid_sections or not file or file.filename == "":
            flash("Fill in a title, choose a path, and select a file.", "error")
            return redirect(url_for("admin_panel"))

        if not allowed_file(file.filename):
            flash("That file type isn't allowed.", "error")
            return redirect(url_for("admin_panel"))

        original_filename = secure_filename(file.filename)
        stored_filename = f"{int(now().timestamp())}_{original_filename}"
        os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
        file.save(os.path.join(config.UPLOAD_FOLDER, stored_filename))

        db = get_db()
        db.execute(
            """INSERT INTO materials (section, title, description, filename, original_filename, uploaded_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (section, title, description, stored_filename, original_filename, session["user_id"]),
        )
        db.commit()
        flash("Material uploaded.", "success")
        return redirect(url_for("admin_panel"))

    db = get_db()
    materials = db.execute("SELECT * FROM materials ORDER BY uploaded_at DESC").fetchall()
    return render_template("admin.html", paths=LEARNING_PATHS, materials=materials)

@app.route("/admin/materials/<int:material_id>/delete", methods=["POST"])
@admin_required
def delete_material(material_id):
    db = get_db()
    material = db.execute("SELECT * FROM materials WHERE id=?", (material_id,)).fetchone()
    if material:
        try:
            os.remove(os.path.join(config.UPLOAD_FOLDER, material["filename"]))
        except OSError:
            pass
        db.execute("DELETE FROM materials WHERE id=?", (material_id,))
        db.commit()
        flash("Material deleted.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute(
        "SELECT id, email, full_name, is_verified, is_admin, is_active, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin_users.html", users=users)
    
@app.route("/admin/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_user_active(user_id):
    if user_id == session["user_id"]:
        flash("You can't deactivate your own account.", "error")
        return redirect(url_for("admin_users"))

    user = get_user_by_id(user_id)
    if not user:
        abort(404)

    db = get_db()
    new_status = 0 if user["is_active"] else 1
    db.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, user_id))
    db.commit()
    flash(f"{user['email']} has been {'reactivated' if new_status else 'deactivated'}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def toggle_user_admin(user_id):
    if user_id == session["user_id"]:
        flash("You can't change your own admin status.", "error")
        return redirect(url_for("admin_users"))

    user = get_user_by_id(user_id)
    if not user:
        abort(404)

    db = get_db()
    new_status = 0 if user["is_admin"] else 1
    db.execute("UPDATE users SET is_admin=? WHERE id=?", (new_status, user_id))
    db.commit()
    flash(f"{user['email']} is now {'an admin' if new_status else 'a regular user'}.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session["user_id"]:
        flash("You can't delete your own account.", "error")
        return redirect(url_for("admin_users"))

    user = get_user_by_id(user_id)
    if not user:
        abort(404)

    db = get_db()
    # Materials they uploaded stay on the site (uploaded_by just becomes
    # unattributed) instead of being force-deleted along with the account.
    db.execute("UPDATE materials SET uploaded_by=NULL WHERE uploaded_by=?", (user_id,))
    # Their reactions/comments cascade-delete automatically (ON DELETE CASCADE).
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash(f"{user['email']} has been deleted.", "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------------------------
# My Profile (account settings for any logged-in user, admin or not)
# ---------------------------------------------------------------------------
@app.route("/profile")
@login_required
def profile():
    user = get_user_by_id(session["user_id"])
    return render_template("profile.html", user=user)


@app.route("/profile/theme", methods=["POST"])
@login_required
def set_theme():
    theme = request.form.get("theme")
    if theme not in ("dark", "light"):
        abort(400)
    db = get_db()
    db.execute("UPDATE users SET theme=? WHERE id=?", (theme, session["user_id"]))
    db.commit()
    session["theme"] = theme
    flash(f"Switched to {theme} mode.", "success")
    return redirect(url_for("profile"))


def allowed_avatar_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_AVATAR_EXTENSIONS


@app.route("/profile/avatar", methods=["POST"])
@login_required
def upload_avatar():
    file = request.files.get("avatar")
    if not file or file.filename == "":
        flash("Choose an image to upload.", "error")
        return redirect(url_for("profile"))

    if not allowed_avatar_file(file.filename):
        flash("Profile pictures must be PNG, JPG, GIF, or WEBP.", "error")
        return redirect(url_for("profile"))

    os.makedirs(config.AVATAR_FOLDER, exist_ok=True)

    user_id = session["user_id"]
    ext = secure_filename(file.filename).rsplit(".", 1)[1].lower()
    new_filename = f"user_{user_id}.{ext}"

    # Remove any previous avatar for this user, even if it had a different
    # extension, so old files don't pile up.
    for old_ext in ALLOWED_AVATAR_EXTENSIONS:
        old_path = os.path.join(config.AVATAR_FOLDER, f"user_{user_id}.{old_ext}")
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except OSError:
                pass

    file.save(os.path.join(config.AVATAR_FOLDER, new_filename))

    db = get_db()
    db.execute("UPDATE users SET avatar_filename=? WHERE id=?", (new_filename, user_id))
    db.commit()
    flash("Profile picture updated.", "success")
    return redirect(url_for("profile"))


@app.route("/profile/change-password", methods=["POST"])
@login_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_new_password = request.form.get("confirm_new_password", "")

    user = get_user_by_id(session["user_id"])

    if not check_password_hash(user["password_hash"], current_password):
        flash("Your current password is incorrect.", "error")
        return redirect(url_for("profile"))

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("profile"))

    if new_password != confirm_new_password:
        flash("New passwords don't match.", "error")
        return redirect(url_for("profile"))

    db = get_db()
    db.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (generate_password_hash(new_password), session["user_id"]),
    )
    db.commit()
    flash("Password updated.", "success")
    return redirect(url_for("profile"))


@app.route("/profile/delete", methods=["POST"])
@login_required
def delete_own_account():
    user = get_user_by_id(session["user_id"])
    if user["is_admin"]:
        flash("Admins can't delete their own account here — ask another admin.", "error")
        return redirect(url_for("profile"))

    db = get_db()
    db.execute("UPDATE materials SET uploaded_by=NULL WHERE uploaded_by=?", (user["id"],))
    db.execute("DELETE FROM users WHERE id=?", (user["id"],))
    db.commit()
    session.clear()
    flash("Your account has been deleted.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(e):
    return render_template("errors/400.html"), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("errors/500.html"), 500


if __name__ == "__main__":
    app.run(
        debug=os.environ.get("EHH_DEBUG", "0").lower() in {"1", "true", "yes"},
        host=os.environ.get("EHH_HOST", "127.0.0.1"),
        port=int(os.environ.get("EHH_PORT", "5000")),
    )
