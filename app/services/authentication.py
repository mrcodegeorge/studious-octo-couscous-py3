import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
import jwt
from sqlalchemy.orm import Session
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from app.config import settings
from app.database.database import get_db
from app.models.user import User

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(password: str) -> str:
    """Hash a password securely using bcrypt with a strong salt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_access_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired.")
        return None
    except jwt.PyJWTError as e:
        logger.warning(f"Invalid token: {e}")
        return None


def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """FastAPI dependency to extract and validate the authenticated user from bearer token or session."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    payload = verify_access_token(token)
    if payload is None:
        raise credentials_exception
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def authenticate_admin(db: Session, username: str, password: str, client_ip: Optional[str] = None) -> User:
    """
    Authenticate an administrator with account lockout protection.
    Raises HTTPException on failure or lockout.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.warning(f"Login attempt for non-existent user '{username}' from IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check if account is locked
    now = datetime.now(timezone.utc)
    if user.locked_until:
        # Normalize timezone
        locked_until_utc = user.locked_until
        if locked_until_utc.tzinfo is None:
            locked_until_utc = locked_until_utc.replace(tzinfo=timezone.utc)
        if now < locked_until_utc:
            remaining = int((locked_until_utc - now).total_seconds() / 60) + 1
            logger.warning(f"Locked account login attempt for '{username}' from IP {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to excessive failed attempts. Try again in {remaining} minute(s)."
            )
        else:
            # Lockout expired, reset counters
            user.locked_until = None
            user.failed_logins = 0
            db.commit()

    if not verify_password(password, user.hashed_password):
        user.failed_logins += 1
        if user.failed_logins >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
            db.commit()
            logger.error(f"User '{username}' exceeded max login attempts. Account locked for {settings.LOCKOUT_DURATION_MINUTES} minutes.")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Too many failed login attempts. Account locked for {settings.LOCKOUT_DURATION_MINUTES} minutes."
            )
        db.commit()
        remaining_attempts = settings.MAX_LOGIN_ATTEMPTS - user.failed_logins
        logger.warning(f"Failed login attempt for '{username}' ({user.failed_logins}/{settings.MAX_LOGIN_ATTEMPTS})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid credentials. {remaining_attempts} attempt(s) remaining before lockout."
        )

    # Successful login
    user.failed_logins = 0
    user.locked_until = None
    user.last_login = now
    db.commit()
    return user
