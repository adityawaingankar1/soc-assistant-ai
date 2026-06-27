import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM")

# Used to build real links in emails (set this in env)
# Examples:
#   https://your-frontend-domain.com
#   http://localhost:3000
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# Comma-separated admin emails for notifications (optional)
# Example: "admin1@company.com,admin2@company.com"
ADMIN_NOTIFICATION_EMAILS = [
    e.strip() for e in (os.getenv("ADMIN_NOTIFICATION_EMAILS", "")).split(",") if e.strip()
]


def _send_email(recipient_email: str, subject: str, html: str, text: str | None = None) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = SMTP_FROM
        msg["To"] = recipient_email
        msg["Subject"] = subject

        if text:
            msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))

        # Basic SMTP send (STARTTLS)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)

            server.sendmail(SMTP_FROM, recipient_email, msg.as_string())

        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


def send_welcome_email(
    recipient_email: str,
    username: str,
    role: str
) -> bool:
    try:
        # STEP 4 — Add Nice HTML Template (replaced body)
        html = f"""
<!DOCTYPE html>
<html>
<head>
<style>

body {{
    background: #f6f8fb;
    font-family: Arial, sans-serif;
}}

.card {{
    max-width: 600px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 12px;
}}

.header {{
    background: #0f172a;
    color: white;
    padding: 20px;
    text-align: center;
}}

.info {{
    border-collapse: collapse;
    width: 100%;
}}

.info td {{
    border: 1px solid #ddd;
    padding: 10px;
}}

.footer {{
    color: #666;
    font-size: 12px;
}}

</style>
</head>

<body>

<div class="card">

<div class="header">
<h2>🛡️ SOC Assistant</h2>
</div>

<p>Hello <b>{username}</b>,</p>

<p>
Your account has been successfully created.
</p>

<table class="info">

<tr>
<td><b>Username</b></td>
<td>{username}</td>
</tr>

<tr>
<td><b>Role</b></td>
<td>{role}</td>
</tr>

<tr>
<td><b>Email</b></td>
<td>{recipient_email}</td>
</tr>

</table>

<br>

<p>
You can now log in and begin using SOC Assistant.
</p>

<br>

<p class="footer">
SOC Assistant Security Platform
</p>

</div>

</body>
</html>
"""

        text = (
            "Welcome to SOC Assistant\n\n"
            f"Hello {username},\n\n"
            "Your account has been successfully created.\n\n"
            f"Username: {username}\n"
            f"Role: {role}\n"
            f"Email: {recipient_email}\n\n"
            "You can now log in and begin using SOC Assistant.\n\n"
            "SOC Assistant Security Platform\n"
        )

        return _send_email(
            recipient_email=recipient_email,
            subject="Welcome to SOC Assistant",
            html=html,
            text=text
        )
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


# ━━━━━━━━━━━━━━━━━━━
# STEP 5 — Password Reset Email
# ━━━━━━━━━━━━━━━━━━━
def send_password_reset_email(
    recipient_email: str,
    token: str
) -> bool:
    """
    Sends a real password reset link (configure APP_BASE_URL).
    Example link generated:
      {APP_BASE_URL}/reset-password?token=...
    """
    try:
        reset_link = (
            f"{APP_BASE_URL}/reset-password?token={token}"
            if APP_BASE_URL
            else token  # fallback if APP_BASE_URL isn't configured
        )

        html = f"""
<!DOCTYPE html>
<html>
<head>
<style>
body {{
    background: #f6f8fb;
    font-family: Arial, sans-serif;
}}
.card {{
    max-width: 600px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 12px;
}}
.header {{
    background: #0f172a;
    color: white;
    padding: 20px;
    text-align: center;
}}
.footer {{
    color: #666;
    font-size: 12px;
}}
a.button {{
    display: inline-block;
    background: #0f172a;
    color: #ffffff !important;
    padding: 12px 18px;
    border-radius: 10px;
    text-decoration: none;
}}
.code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    background: #f1f5f9;
    padding: 10px;
    border-radius: 10px;
    word-break: break-all;
}}
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h2>Password Reset</h2>
    </div>

    <p>You requested a password reset for your SOC Assistant account.</p>

    <p>
      <a class="button" href="{reset_link}">Reset Password</a>
    </p>

    <p>If the button doesn’t work, copy and paste this link into your browser:</p>
    <div class="code">{reset_link}</div>

    <br />
    <p class="footer">
      If you didn’t request this, you can ignore this email.
    </p>
  </div>
</body>
</html>
"""

        text = (
            "SOC Assistant — Password Reset\n\n"
            "You requested a password reset.\n\n"
            f"Reset link/token:\n{reset_link}\n\n"
            "If you didn’t request this, you can ignore this email.\n"
        )

        return _send_email(
            recipient_email=recipient_email,
            subject="Reset your SOC Assistant password",
            html=html,
            text=text
        )
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


# ━━━━━━━━━━━━━━━━━━━
# STEP 6 — Admin Notification (email-based implementation)
# ━━━━━━━━━━━━━━━━━━━
def send_admin_notification_email(username: str, email: str, role: str) -> bool:
    """
    Sends an admin notification email to ADMIN_NOTIFICATION_EMAILS (env var).
    If you use Celery, call this function inside your task.
    """
    if not ADMIN_NOTIFICATION_EMAILS:
        return True  # no admins configured; treat as non-fatal

    subject = "New user registered"
    text_body = (
        "New user registered:\n\n"
        f"Username: {username}\n"
        f"Role: {role}\n"
        f"Email: {email}\n"
    )

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
<style>
body {{ background: #f6f8fb; font-family: Arial, sans-serif; }}
.card {{ max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 12px; }}
pre {{ background: #f1f5f9; padding: 12px; border-radius: 10px; }}
</style>
</head>
<body>
  <div class="card">
    <h3>New user registered:</h3>
    <pre>Username: {username}
Role: {role}
Email: {email}</pre>
  </div>
</body>
</html>
"""

    ok = True
    for admin_email in ADMIN_NOTIFICATION_EMAILS:
        ok = _send_email(admin_email, subject, html_body, text_body) and ok
    return ok


# ━━━━━━━━━━━━━━━━━━━
# STEP 7 — Security Notifications (generic helper)
# ━━━━━━━━━━━━━━━━━━━
def send_security_notification_email(recipient_email: str, subject: str, message: str) -> bool:
    """
    Generic notification helper for events like:
    - password changed
    - role changed
    - account disabled
    - account restored
    - Google account linked
    """
    html = f"""
<!DOCTYPE html>
<html>
<head>
<style>
body {{ background: #f6f8fb; font-family: Arial, sans-serif; }}
.card {{ max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 12px; }}
.header {{ background: #0f172a; color: white; padding: 14px; text-align: center; border-radius: 10px; }}
.footer {{ color: #666; font-size: 12px; }}
</style>
</head>
<body>
  <div class="card">
    <div class="header"><h3>{subject}</h3></div>
    <p>{message}</p>
    <p class="footer">SOC Assistant Security Platform</p>
  </div>
</body>
</html>
"""
    text = f"{subject}\n\n{message}\n\nSOC Assistant Security Platform\n"
    return _send_email(recipient_email=recipient_email, subject=subject, html=html, text=text)