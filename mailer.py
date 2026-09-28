import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import settings as config

logger = logging.getLogger(__name__)


def send_email(to_address: str, subject: str, body: str) -> bool:
    """
    Sends an email. If SMTP credentials are not configured (see settings.py),
    falls back to printing the email to the console so the flow can still
    be tested end-to-end during development.

    Returns True if a real email was sent, False if it fell back to console.
    """
    if not config.EMAIL_CONFIGURED:
        if not config.CONSOLE_EMAIL_ENABLED:
            print("EHH email delivery is unavailable: SMTP is not configured.")
            return False
        print("\n" + "=" * 60)
        print("EHH CONSOLE-MODE EMAIL (no SMTP credentials configured)")
        print(f"To:      {to_address}")
        print(f"Subject: {subject}")
        print("-" * 60)
        print(body)
        print("=" * 60 + "\n")
        return False

    msg = MIMEMultipart()
    msg["From"] = config.MAIL_FROM
    msg["To"] = to_address
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(config.MAIL_SERVER, config.MAIL_PORT, timeout=20) as server:
            server.starttls()
            server.login(config.MAIL_USERNAME, config.MAIL_PASSWORD)
            server.sendmail(config.MAIL_FROM, [to_address], msg.as_string())
    except (OSError, smtplib.SMTPException):
        logger.exception("SMTP delivery failed for %s", to_address)
        return False
    return True


def send_verification_code(to_address: str, code: str) -> bool:
    subject = "Verify your E.H.H. account"
    body = (
        f"Welcome to Ethical Hacking Hub!\n\n"
        f"Your verification code is: {code}\n\n"
        f"Enter this code on the verification page to activate your account.\n"
        f"This code expires in 15 minutes.\n\n"
        f"If you didn't create an account with E.H.H., you can ignore this email."
    )
    return send_email(to_address, subject, body)


def send_reset_code(to_address: str, code: str) -> bool:
    subject = "Reset your E.H.H. password"
    body = (
        f"We received a request to reset your Ethical Hacking Hub password.\n\n"
        f"Your reset code is: {code}\n\n"
        f"Enter this code on the reset page to choose a new password.\n"
        f"This code expires in 15 minutes.\n\n"
        f"If you didn't request this, you can ignore this email."
    )
    return send_email(to_address, subject, body)
