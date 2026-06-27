# backend/api/routes_auth.py
import secrets
import re
from datetime import datetime, timedelta
from backend.utils.email_service import send_welcome_email
from backend.tasks.email_tasks import (
    send_welcome_email_task
)

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel, field_validator
from loguru import logger

from firebase_admin import auth as firebase_auth  # <-- ADDED

from backend.config import get_settings
from backend.database import get_db, User, KnowledgeBaseDocument, SystemLog
from backend.auth import (
    SignupRequest,
    LoginRequest,
    ChangePasswordRequest,
    Token,
    TokenData,
    hash_password,
    verify_password,
    validate_password,
    create_access_token,
    get_current_user,
    require_role,
)
from backend.utils.pii import redact_pii_keys, redact_pii_strings

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

_reset_tokens: dict = {}


class ForgotPasswordRequest(BaseModel):
    email: str

    model_config = {
        "json_schema_extra": {
            "example": {"email": "john@company.com"}
        }
    }


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_password(cls, v):
        result = validate_password(v)
        if not result["valid"]:
            raise ValueError(
                "Password does not meet requirements: " +
                ", ".join(result["errors"])
            )
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "token": "abc123...",
                "new_password": "NewSecure@123"
            }
        }
    }


class UpdateRoleRequest(BaseModel):
    role: str

    model_config = {
        "json_schema_extra": {
            "example": {"role": "analyst"}
        }
    }


# ============================
# ADDED MODEL (Firebase login)
# ============================
class FirebaseLoginRequest(BaseModel):
    firebase_token: str
    email: str | None = None


def _admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == "admin").count()


def _active_admin_count(db: Session) -> int:
    return db.query(User).filter(
        User.role == "admin",
        User.is_active == True
    ).count()


def _admin_count_excluding(db: Session, user_id: str) -> int:
    return db.query(User).filter(
        User.role == "admin",
        User.id != user_id
    ).count()


def _active_admin_count_excluding(db: Session, user_id: str) -> int:
    return db.query(User).filter(
        User.role == "admin",
        User.is_active == True,
        User.id != user_id
    ).count()


@router.get("/signup-check")
def signup_check(db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    return {
        "is_first_user": total_users == 0,
        "total_users": total_users
    }


@router.post("/signup", status_code=201)
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    # Prevent username reuse confusion during grace period by checking original_username too
    existing_user = (
        db.query(User)
        .filter(or_(
            User.username == req.username.lower(),
            User.original_username == req.username.lower()
        ))
        .first()
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"Username '{req.username}' is already taken. Choose another."
        )

    existing_email = (
        db.query(User)
        .filter(or_(
            User.email == req.email.lower(),
            User.original_email == req.email.lower()
        ))
        .first()
    )
    if existing_email:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists."
        )

    total_users = db.query(User).count()
    is_first_admin = total_users == 0
    role = "admin" if is_first_admin else req.role

    if total_users > 0 and role == "admin":
        role = "analyst"

    hashed = hash_password(req.password)

    user = User(
        username=req.username.lower(),
        email=req.email.lower(),
        password_hash=hashed,
        role=role,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    send_welcome_email_task.delay(
        recipient_email=user.email,
        username=user.username,
        role=user.role
    )

    logger.info(
        f"[Auth] New user registered: '{user.username}' ({user.role})"
        f"{' — FIRST ADMIN' if is_first_admin else ''}"
    )

    return {
        "success": True,
        "message": "Account created successfully. You can now log in.",
        "username": user.username,
        "role": user.role,
        "is_first_admin": is_first_admin
    }


# ============================
# FIREBASE LOGIN
# ============================
@router.post("/firebase-login")
def firebase_login(
    req: FirebaseLoginRequest,
    db: Session = Depends(get_db)
):
    # ─────────────────────────────────────────────────────────
    # BACKEND DEBUG (per instructions): log request email first
    # ─────────────────────────────────────────────────────────
    logger.info(f"[Firebase Request] email={req.email}")

    try:
        # Verify Firebase token
        decoded = firebase_auth.verify_id_token(
            req.firebase_token,
            clock_skew_seconds=60
        )

        # Extract Firebase UID
        firebase_uid = decoded.get("uid")
        if not firebase_uid:
            raise HTTPException(
                status_code=400,
                detail="Firebase UID missing"
            )

        # Fetch full Firebase user safely
        firebase_user = firebase_auth.get_user(firebase_uid)

        # ============================
        # FIX 3: triple-fallback email resolution
        # ============================
        email = (
            firebase_user.email
            or req.email
            or decoded.get("email")
        )

        # ADD DEBUG LOG (immediately before the check)
        logger.info(
            f"[Firebase Debug] "
            f"uid={firebase_uid}, "
            f"firebase_user_email={firebase_user.email}, "
            f"request_email={req.email}, "
            f"decoded_email={decoded.get('email')}"
        )

        if not email:
            logger.error(
                f"[Firebase] No email found. "
                f"uid={firebase_uid}, "
                f"firebase_user_email={firebase_user.email}, "
                f"request_email={req.email}, "
                f"decoded_email={decoded.get('email')}"
            )
            raise HTTPException(
                status_code=400,
                detail="Firebase email missing"
            )

        email = email.lower().strip()

        # Lookup existing user
        user = db.query(User).filter(
            User.email == email
        ).first()

        # AUTO PROVISION
        if not user:
            base_username = (
                email.split("@")[0]
                .lower()
                .replace(".", "_")
            )
            username = base_username

            # Ensure unique username
            counter = 1
            while db.query(User).filter(
                User.username == username
            ).first():
                username = f"{base_username}_{counter}"
                counter += 1

            user = User(
                username=username,
                email=email,
                password_hash="firebase_auth",
                role="analyst",
                is_active=True
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            
            send_welcome_email_task.delay(
                recipient_email=user.email,
                username=user.username,
                role=user.role
            )

            logger.info(
                f"[Auth] Auto-provisioned Firebase user: '{user.username}'"
            )

        # Block inactive users
        if (
            not user.is_active
            or getattr(user, "deleted_at", None) is not None
        ):
            raise HTTPException(
                status_code=403,
                detail="Account has been deactivated."
            )

        # Generate backend JWT
        token = create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role
        )

        logger.info(
            f"[Auth] Firebase login success: "
            f"'{user.username}' ({user.role})"
        )

        return {
            "access_token": token,
            "user_id": user.id,
            "username": user.username,
            "role": user.role
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            f"[Firebase Login Error] {e}"
        )
        raise HTTPException(
            status_code=401,
            detail="Google authentication failed."
        )


@router.post("/login", response_model=Token)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    username = req.username.strip().lower()
    user = db.query(User).filter(User.username == username).first()

    if not user or not verify_password(req.password, user.password_hash):
        logger.warning(f"[Auth] Failed login for username='{username}'")
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password. Please try again."
        )

    # Enterprise: block deleted users too
    if (not user.is_active) or (getattr(user, "deleted_at", None) is not None):
        raise HTTPException(
            status_code=403,
            detail="Your account has been deactivated or deleted. Contact an administrator."
        )

    token = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role
    )

    logger.info(f"[Auth] Login: '{user.username}' ({user.role})")
    return Token(
        access_token=token,
        user_id=user.id,
        username=user.username,
        role=user.role
    )


@router.get("/me")
def get_me(
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }


@router.get("/verify")
def verify_token(current_user: TokenData = Depends(get_current_user)):
    return {
        "valid": True,
        "user_id": current_user.user_id,
        "username": current_user.username,
        "role": current_user.role
    }


@router.post("/logout")
def logout(current_user: TokenData = Depends(get_current_user)):
    logger.info(f"[Auth] Logout: '{current_user.username}'")
    return {
        "success": True,
        "message": "Logged out successfully. Please delete your local token."
    }


@router.put("/change-password")
def change_password(
    req: ChangePasswordRequest,
    current_user: TokenData = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect."
        )

    if req.current_password == req.new_password:
        raise HTTPException(
            status_code=400,
            detail="New password must be different from your current password."
        )

    user.password_hash = hash_password(req.new_password)
    db.commit()

    logger.info(f"[Auth] Password changed for '{user.username}'")
    return {
        "success": True,
        "message": "Password changed successfully. Please log in again."
    }


@router.get("/password-rules")
def get_password_rules():
    return {
        "rules": [
            {"id": "length", "label": "At least 8 characters", "regex": ".{8,}"},
            {"id": "uppercase", "label": "At least 1 uppercase letter (A–Z)", "regex": "[A-Z]"},
            {"id": "lowercase", "label": "At least 1 lowercase letter (a–z)", "regex": "[a-z]"},
            {"id": "number", "label": "At least 1 number (0–9)", "regex": "\\d"},
            {"id": "special", "label": "At least 1 special character (!@#$%...)", "regex": "[!@#$%^&*]"}
        ],
        "username_rules": {
            "min_length": 3,
            "max_length": 30,
            "allowed": "Letters, numbers, underscores only"
        }
    }


@router.get("/users")
def list_users(
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    users = db.query(User).order_by(User.created_at).all()
    return {
        "total": len(users),
        "users": [u.to_dict() for u in users]
    }


@router.put("/users/{user_id}/role")
def update_user_role(
    user_id: str,
    req: UpdateRoleRequest,
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    allowed_roles = {"admin", "analyst", "viewer"}
    new_role = req.role.lower()
    if new_role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Must be one of: {sorted(allowed_roles)}"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.user_id and new_role != "admin":
        raise HTTPException(
            status_code=400,
            detail="You cannot change your own admin role."
        )

    if user.role == "admin" and new_role != "admin":
        remaining_admins = _admin_count_excluding(db, user.id)
        if remaining_admins < 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote this admin because it would leave the system without an admin."
            )

    old_role = user.role
    user.role = new_role
    db.commit()

    logger.info(
        f"[Auth] Role updated: '{user.username}' "
        f"{old_role} → {user.role} "
        f"(by '{current_user.username}')"
    )

    return {
        "success": True,
        "username": user.username,
        "old_role": old_role,
        "new_role": user.role
    }


@router.put("/users/{user_id}/toggle")
def toggle_user_active(
    user_id: str,
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot deactivate your own account."
        )

    if getattr(user, "deleted_at", None) is not None:
        raise HTTPException(
            status_code=400,
            detail="Cannot toggle a deleted user. Use the restore endpoint."
        )

    if user.role == "admin" and user.is_active:
        remaining_active_admins = _active_admin_count_excluding(db, user.id)
        if remaining_active_admins < 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot deactivate this admin because it would leave the system without an active admin."
            )

    user.is_active = not user.is_active
    db.commit()

    action = "activated" if user.is_active else "deactivated"
    logger.info(
        f"[Auth] User {action}: '{user.username}' "
        f"(by '{current_user.username}')"
    )

    return {
        "success": True,
        "username": user.username,
        "is_active": user.is_active,
        "message": f"User '{user.username}' has been {action}."
    }


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """
    Enterprise-grade delete:
    - Soft delete immediately (deleted_at, is_active=False)
    - Pseudonymize username/email to remove PII from joins/UI
    - Preserve SOC evidence (alerts, audit trails, etc.)
    - Redact PII strings + PII keys from audit JSON payloads
    - Chat is purged later by background job (retention window)
    """
    settings = get_settings()
    retention_days = settings.user_chat_purge_days

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == current_user.user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account."
        )

    if user.role == "admin" and user.is_active:
        remaining_active_admins = _active_admin_count_excluding(db, user.id)
        if remaining_active_admins < 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete this admin because it would leave the system without an active admin."
            )

    if getattr(user, "deleted_at", None) is not None:
        return {"success": True, "message": "User already soft-deleted."}

    try:
        now = datetime.utcnow()

        # Preserve originals for restore during grace period + prevent reuse confusion
        user.original_username = user.username
        user.original_email = user.email

        # Pseudonymize identity (must satisfy username rules: letters/numbers/underscore)
        safe_token = (user.id or "").replace("-", "")[:16]
        user.username = f"deleted_{safe_token}"
        user.email = f"deleted_{user.id}@example.invalid"

        user.is_active = False
        user.deleted_at = now
        user.deleted_by_user_id = current_user.user_id

        # KB inventory: remove uploader username display (PII surface)
        db.query(KnowledgeBaseDocument).filter(
            KnowledgeBaseDocument.uploaded_by_user_id == user_id
        ).update(
            {KnowledgeBaseDocument.uploaded_by_username: "[deleted]"},
            synchronize_session=False
        )

        # Redact PII from audit logs event_data
        pii_values = {user.original_username or "", user.original_email or ""}
        logs = db.query(SystemLog).filter(SystemLog.user_id == user_id).all()
        for log in logs:
            if isinstance(log.event_data, (dict, list)):
                cleaned = log.event_data

                # key-based scrub (username/email/etc.)
                if settings.audit_strip_pii_keys:
                    cleaned = redact_pii_keys(cleaned, placeholder=settings.audit_pii_placeholder)

                # value-based scrub (if username/email embedded in strings)
                cleaned = redact_pii_strings(cleaned, pii_values, placeholder="[deleted]")
                log.event_data = cleaned

        db.commit()

        logger.info(
            f"[Auth] User soft-deleted: '{user.original_username}' "
            f"(by '{current_user.username}')"
        )

        return {
            "success": True,
            "message": (
                f"User soft-deleted. Access revoked immediately; SOC history retained; "
                f"chat will be purged after {retention_days} days."
            )
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Soft delete failed: {str(e)}")


@router.post("/users/{user_id}/restore")
def restore_user(
    user_id: str,
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    """
    Restore a soft-deleted user (only before purge and within grace window).
    """
    settings = get_settings()
    retention_days = settings.user_chat_purge_days

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if getattr(user, "deleted_at", None) is None:
        raise HTTPException(status_code=400, detail="User is not deleted.")

    if getattr(user, "purged_at", None) is not None:
        raise HTTPException(status_code=400, detail="User is already purged and cannot be restored.")

    # Restore only inside grace window
    if user.deleted_at and user.deleted_at <= (datetime.utcnow() - timedelta(days=retention_days)):
        raise HTTPException(
            status_code=400,
            detail=f"User deletion is beyond the {retention_days}-day grace period and cannot be restored."
        )

    if not user.original_username or not user.original_email:
        raise HTTPException(status_code=400, detail="Original identity is not available for restore.")

    # Ensure originals are not taken (including other users' original_* during grace)
    username_taken = (
        db.query(User)
        .filter(User.id != user.id)
        .filter(or_(
            User.username == user.original_username,
            User.original_username == user.original_username
        ))
        .first()
    )
    if username_taken:
        raise HTTPException(status_code=409, detail="Cannot restore: original username is already taken.")

    email_taken = (
        db.query(User)
        .filter(User.id != user.id)
        .filter(or_(
            User.email == user.original_email,
            User.original_email == user.original_email
        ))
        .first()
    )
    if email_taken:
        raise HTTPException(status_code=409, detail="Cannot restore: original email is already taken.")

    try:
        user.username = user.original_username
        user.email = user.original_email

        user.original_username = None
        user.original_email = None
        user.deleted_at = None
        user.deleted_by_user_id = None
        user.is_active = True

        db.commit()

        logger.info(
            f"[Auth] User restored: '{user.username}' "
            f"(restored by '{current_user.username}')"
        )

        return {"success": True, "message": f"User '{user.username}' restored successfully."}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")


@router.post("/forgot-password")
def forgot_password(
    req: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    email = req.email.strip().lower()
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        raise HTTPException(
            status_code=400,
            detail="Invalid email address format."
        )

    user = db.query(User).filter(User.email == email).first()

    # If user is inactive/deleted, do not issue reset tokens
    if user and user.is_active and getattr(user, "deleted_at", None) is None:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=30)

        _reset_tokens[token] = {
            "user_id": user.id,
            "username": user.username,
            "email": email,
            "expires_at": expires_at,
            "used": False
        }

        logger.info(
            f"[Auth] Password reset requested for '{user.username}' ({email})"
        )

        return {
            "success": True,
            "demo_token": token,
            "expires_in": "30 minutes",
            "message": (
                "DEMO MODE: In production this token would be sent to "
                f"'{email}'. Copy the token below to reset your password."
            )
        }

    return {
        "success": True,
        "demo_token": None,
        "expires_in": "30 minutes",
        "message": (
            "DEMO MODE: If an account exists with this email, "
            "a reset token would appear here."
        )
    }


@router.post("/reset-password")
def reset_password(
    req: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    token_data = _reset_tokens.get(req.token)
    if not token_data:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token. Please request a new one."
        )

    if token_data.get("used"):
        raise HTTPException(
            status_code=400,
            detail="This reset token has already been used. Please request a new one."
        )

    if datetime.utcnow() > token_data["expires_at"]:
        del _reset_tokens[req.token]
        raise HTTPException(
            status_code=400,
            detail="Reset token has expired (30 minute limit). Please request a new one."
        )

    user = db.query(User).filter(User.id == token_data["user_id"]).first()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="Associated user account not found."
        )

    if (not user.is_active) or (getattr(user, "deleted_at", None) is not None):
        raise HTTPException(
            status_code=403,
            detail="This account has been deactivated or deleted."
        )

    user.password_hash = hash_password(req.new_password)
    db.commit()

    _reset_tokens[req.token]["used"] = True
    del _reset_tokens[req.token]

    logger.info(f"[Auth] Password reset successfully for '{user.username}'")

    return {
        "success": True,
        "username": user.username,
        "message": "Password reset successfully. You can now log in with your new password."
    }