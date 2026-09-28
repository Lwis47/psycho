# Ethical Hacking Hub (E.H.H.)

A learning platform for cybersecurity / ethical hacking education.

**Frontend:** HTML + CSS (Jinja2 templates, no JS framework — just a small amount of
vanilla behavior via native browser features).
**Backend:** Python (Flask) + SQLite (built into Python, no database server to install).

## Features

- Landing page with a hero illustration and log in / sign up call-to-actions
- Sign up with email + password
- **Email verification**: a 6-digit code is emailed to the user; they must enter it
  before they can log in
- **Log in** with email + password (blocked until email is verified)
- **Forgot password**: a reset code is emailed; entering it lets the user set a new
  password
- **Dashboard** with 12 admin-managed cybersecurity learning paths: Network Security,
  Web Exploitation, Penetration Testing, Malware Analysis, Digital Forensics,
  Cryptography, Programming for Security, Nmap & Network Scanning, Linux & Command Line,
  OSINT & Digital Research, Cloud Security, and Incident Response
- A **Linux distributions** page linking to official downloads of security-focused
  distros (Kali, Parrot OS, BlackArch, etc.)
- **Admin panel**: the admin can upload learning materials (PDFs, slides, zips, etc.)
  to any learning path; they immediately appear on that path's page and on the
  dashboard's "recently added" list, downloadable by any logged-in user
- **About** and **Developer** pages, linked from icons in the top navigation

## Quick start

```bash
# 1. Install the one dependency
pip install -r requirements.txt

# 2. Run it
python app.py
```

Then open **http://localhost:5000** in your browser.

A SQLite database file is created automatically at `instance/ehh.db` the first time
you run the app — nothing else to set up.

## Setting up real email sending

Out of the box, E.H.H. runs in **console mode**: verification codes and password
reset codes are printed to your terminal instead of emailed, so you can test the
whole signup → verify → login flow immediately without any email setup.

To send real emails, open `config.py` and fill in your SMTP credentials:

```python
MAIL_SERVER   = "smtp.gmail.com"
MAIL_PORT     = 587
MAIL_USERNAME = "yourname@gmail.com"
MAIL_PASSWORD = "your 16-character Gmail App Password"   # not your normal password
```

For Gmail specifically, you need an **App Password** (Google Account → Security →
2-Step Verification → App passwords) — your regular password won't work over SMTP.
SendGrid, Mailgun, and most other providers work the same way with their own host/
port/credentials — see the comments in `config.py` for a SendGrid example.

You can also set these as environment variables instead of editing the file
(`EHH_MAIL_SERVER`, `EHH_MAIL_USERNAME`, `EHH_MAIL_PASSWORD`, etc.) — useful if you
deploy this somewhere and don't want credentials in the code.

## Making yourself the admin

In `config.py`:

```python
ADMIN_EMAIL = "admin@ehh.local"
```

Change this to your own email **before** signing up with it. The very first account
created with that exact email address is automatically granted admin rights and can
access `/admin` to upload materials. (If you've already signed up with a different
email and want admin rights, just update the `is_admin` column for your row in
`instance/ehh.db`, or delete the database and start over.)

## Project structure

```
ehh/
├── app.py                # All routes: auth, verification, dashboard, admin, etc.
├── config.py              # Secret key, email/SMTP settings, admin email
├── db.py                  # SQLite connection + schema
├── mailer.py               # Sends verification/reset emails (or prints them)
├── requirements.txt
├── templates/             # Jinja2 HTML templates
│   ├── base.html            # Shared layout, nav, flash messages, footer
│   ├── index.html           # Landing page
│   ├── signup.html / verify.html
│   ├── login.html / forgot_password.html / reset_password.html
│   ├── dashboard.html / path_detail.html
│   ├── linux_distros.html
│   ├── about.html / developer.html
│   ├── admin.html
│   └── partials/            # Shared path icons + material actions
├── static/css/style.css   # All styling
├── static/js/site.js      # Navigation and form interactions
└── uploads/                # Uploaded learning materials get stored here
```

## Customizing

- **Developer page**: edit `templates/developer.html` with your real name, bio, and
  contact/social links.
- **Learning paths**: edit the `LEARNING_PATHS` list near the top of `app.py` to
  rename, add, or remove paths.
- **Linux distros list**: edit the `LINUX_DISTROS` list in `app.py`.
- **Colors/fonts**: all design tokens are CSS variables at the top of
  `static/css/style.css` (`--bg`, `--accent`, `--font-mono`, etc.) — change them once
  and the whole site updates.

## Before deploying publicly

This is a working prototype suited for local use, a class project, or a small private
deployment. Before putting it on the public internet:

- Set a strong, random `SECRET_KEY` in `config.py` (or via the `EHH_SECRET_KEY`
  environment variable) — don't use the default.
- Run it behind a real WSGI server (e.g. `gunicorn app:app`) instead of the Flask
  development server used by `python app.py`.
- Serve it over HTTPS.
- Consider rate-limiting the signup/login/reset endpoints to slow down abuse.

## Deploying the class project on Render

This repository includes `render.yaml` for a free Render web service. Create a
new **Blueprint** in Render, select this repository, and Render will install the
dependencies and start the site with Gunicorn.

Render generates `EHH_SECRET_KEY` automatically. During the first Blueprint
setup, enter these environment variables in Render instead of adding them to a
file or committing them to Git:

- `EHH_ADMIN_EMAIL` — the email address that should receive admin access.
- `EHH_MAIL_SERVER`, `EHH_MAIL_USERNAME`, `EHH_MAIL_PASSWORD`, and
  `EHH_MAIL_FROM` — SMTP details required for verification and password-reset
  emails. `EHH_MAIL_PORT` is already set to `587`.

For a temporary class project, Render's free plan is a good fit. Its local disk
is not persistent, so uploaded materials, newly created accounts, and other
SQLite changes can be lost after a redeploy or restart. The materials already
tracked in this repository are included on every new deployment.
