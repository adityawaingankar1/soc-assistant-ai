"""
Authentication & Authorization Module

Database: SQLite (soc_assistant.db) → users table
Passwords: bcrypt hashed (rounds=12)
Tokens: JWT (HS256, 8hr expiry)
"""

import re
import bcrypt
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database import get_db, User  # IMPORTANT: DB validation for deleted/inactive users

settings = get_settings()
bearer = HTTPBearer(auto_error=False)

SECRET_KEY = settings.secret_key
ALGORITHM = "HS256"
EXPIRE_MIN = 480  # 8 hours

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,30}$')
PASSWORD_MIN_LEN = 8


def validate_username(username: str) -> str:
    if not username or not username.strip():
        raise ValueError("Username is required")

    username = username.strip()

    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters")

    if len(username) > 30:
        raise ValueError("Username must be at most 30 characters")

    if not USERNAME_PATTERN.match(username):
        raise ValueError("Username can only contain letters, numbers, and underscores")

    return username.lower()


def validate_email(email: str) -> str:
    if not email or not email.strip():
        raise ValueError("Email is required")

    email = email.strip().lower()
    pattern = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

    if not pattern.match(email):
        raise ValueError("Invalid email address format")

    return email


def validate_password(password: str) -> dict:
    errors = []

    if len(password) < PASSWORD_MIN_LEN:
        errors.append(f"At least {PASSWORD_MIN_LEN} characters")
    if not re.search(r'[A-Z]', password):
        errors.append("At least 1 uppercase letter (A-Z)")
    if not re.search(r'[a-z]', password):
        errors.append("At least 1 lowercase letter (a-z)")
    if not re.search(r'\d', password):
        errors.append("At least 1 number (0-9)")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errors.append("At least 1 special character (!@#$%^&*...)")

    return {"valid": len(errors) == 0, "errors": errors}


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"

    @field_validator("username")
    @classmethod
    def check_username(cls, v):
        return validate_username(v)

    @field_validator("email")
    @classmethod
    def check_email(cls, v):
        return validate_email(v)

    @field_validator("password")
    @classmethod
    def check_password(cls, v):
        result = validate_password(v)
        if not result["valid"]:
            raise ValueError("Password does not meet requirements: " + ", ".join(result["errors"]))
        return v

    @field_validator("role")
    @classmethod
    def check_role(cls, v):
        allowed = {"admin", "analyst", "viewer"}
        if v.lower() not in allowed:
            raise ValueError(f"Role must be one of: {sorted(allowed)}")
        return v.lower()


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v):
        result = validate_password(v)
        if not result["valid"]:
            raise ValueError("New password does not meet requirements: " + ", ".join(result["errors"]))
        return v


class TokenData(BaseModel):
    user_id: str
    username: str
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str
    expires_in: int = EXPIRE_MIN * 60


def create_access_token(user_id: str, username: str, role: str) -> str:
    now = datetime.utcnow()
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=EXPIRE_MIN)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(user_id=payload["sub"], username=payload["username"], role=payload["role"])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token. Please log in again."
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db)
) -> TokenData:
    """
    Enterprise-safe: validates user state in DB on every request.
    Soft-deleted or inactive users are blocked immediately (even if JWT is valid).
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in."
        )

    token_data = decode_token(credentials.credentials)

    user = db.query(User).filter(User.id == token_data.user_id).first()
    if (not user) or (not user.is_active) or (getattr(user, "deleted_at", None) is not None):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account inactive or deleted. Please contact an administrator."
        )

    return token_data


def require_role(*roles: str):
    def checker(user: TokenData = Depends(get_current_user)) -> TokenData:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role(s): {list(roles)}. Your role: '{user.role}'"
            )
        return user
    return checker


require_admin = require_role("admin")
require_analyst = require_role("admin", "analyst")
require_viewer = require_role("admin", "analyst", "viewer")