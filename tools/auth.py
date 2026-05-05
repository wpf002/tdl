"""Auth helpers: password hashing, session cookies, one-time tokens, email.

Sessions: signed cookie via itsdangerous. Cookie value is a signed payload
containing the user_id and an issued-at timestamp. Validity window enforced
on read; no DB row per session.

One-time tokens (verify_email, reset_password): a 32-byte URL-safe token is
generated and emailed to the user; sha256(token) is stored in `auth_tokens`.
On consumption we sha256 the submitted plaintext and look up the row.
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SESSION_COOKIE_NAME = "tdl_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30  # 30 days

VERIFY_EMAIL_TTL = timedelta(hours=24)
RESET_PASSWORD_TTL = timedelta(hours=1)

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 200  # bcrypt truncates at 72 bytes; we cap before hashing


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _session_serializer():
    secret = os.environ.get("SESSION_SECRET")
    if not secret:
        raise RuntimeError("SESSION_SECRET env var is not set")
    return URLSafeTimedSerializer(secret, salt="tdl-session-v1")


# ── Passwords ────────────────────────────────────────────────────────────────

def hash_password(plaintext: str) -> str:
    if not isinstance(plaintext, str):
        raise ValueError("password must be a string")
    # bcrypt has a 72-byte limit; reject inputs that would silently truncate.
    if len(plaintext.encode("utf-8")) > 72:
        raise ValueError("password too long")
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plaintext: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def validate_password_strength(plaintext: str) -> str | None:
    """Return None if OK, or a human-readable error string."""
    if not isinstance(plaintext, str):
        return "Password is required."
    if len(plaintext) < PASSWORD_MIN_LENGTH:
        return f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
    if len(plaintext.encode("utf-8")) > 72:
        return "Password is too long (max 72 bytes)."
    return None


# ── Email normalization ─────────────────────────────────────────────────────

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def looks_like_email(email: str) -> bool:
    if not email or "@" not in email:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain and len(email) <= 255


# ── Session cookies ──────────────────────────────────────────────────────────

def issue_session_cookie(user_id: str) -> str:
    return _session_serializer().dumps({"uid": user_id})


def read_session_cookie(value: str) -> str | None:
    if not value:
        return None
    try:
        data = _session_serializer().loads(value, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict):
        return None
    uid = data.get("uid")
    return uid if isinstance(uid, str) else None


def session_cookie_kwargs():
    """kwargs for Flask response.set_cookie that match our security model."""
    is_prod = os.environ.get("FLASK_ENV") != "development" and os.environ.get("RAILWAY_ENVIRONMENT") is not None
    return dict(
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=is_prod,         # required in production; localhost dev uses http
        samesite="Lax",
        path="/",
    )


# ── One-time tokens (email verification, password reset) ────────────────────

def generate_token() -> tuple[str, str]:
    """Return (plaintext, sha256_hex). Plaintext is emailed to the user;
    only the hash is persisted in the auth_tokens table."""
    plaintext = secrets.token_urlsafe(32)
    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return plaintext, digest


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def token_expiry(purpose: str) -> str:
    if purpose == "verify_email":
        return (datetime.now(timezone.utc) + VERIFY_EMAIL_TTL).isoformat()
    if purpose == "reset_password":
        return (datetime.now(timezone.utc) + RESET_PASSWORD_TTL).isoformat()
    raise ValueError(f"unknown token purpose: {purpose}")


def is_token_expired(expires_at_iso: str) -> bool:
    try:
        dt = datetime.fromisoformat(expires_at_iso)
    except ValueError:
        return True
    return datetime.now(timezone.utc) >= dt


# ── Email (Resend) ───────────────────────────────────────────────────────────

def _email_from() -> str:
    return os.environ.get("EMAIL_FROM") or "TDL Playbook <onboarding@resend.dev>"


def _app_base_url() -> str:
    return (os.environ.get("APP_BASE_URL") or "http://localhost:5173").rstrip("/")


def send_verification_email(to_email: str, token: str) -> None:
    link = f"{_app_base_url()}/#/verify-email?token={token}"
    _send_email(
        to=to_email,
        subject="Verify your TDL Playbook email",
        html=(
            f"<p>Click the link below to verify your email address:</p>"
            f'<p><a href="{link}">{link}</a></p>'
            f"<p>This link expires in 24 hours.</p>"
        ),
    )


def send_password_reset_email(to_email: str, token: str) -> None:
    link = f"{_app_base_url()}/#/reset-password?token={token}"
    _send_email(
        to=to_email,
        subject="Reset your TDL Playbook password",
        html=(
            f"<p>Click the link below to reset your password:</p>"
            f'<p><a href="{link}">{link}</a></p>'
            f"<p>This link expires in 1 hour. If you did not request this, ignore this email.</p>"
        ),
    )


def _send_email(to: str, subject: str, html: str) -> None:
    api_key = os.environ.get("RESEND_API_KEY")
    if not api_key:
        # Dev fallback: log to stderr so you can copy the link by hand.
        import sys
        print(f"[email-stub] to={to} subject={subject!r}\n{html}", file=sys.stderr, flush=True)
        return
    import resend
    resend.api_key = api_key
    resend.Emails.send({
        "from": _email_from(),
        "to": [to],
        "subject": subject,
        "html": html,
    })
