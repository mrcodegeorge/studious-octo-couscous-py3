from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.migrations import is_initial_setup_needed
from app.models.user import User
from app.services.authentication import (
    authenticate_admin,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password
)
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class SetupAdminRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: Optional[str] = None
    password: str = Field(min_length=8)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class UserResponse(BaseModel):
    id: int
    uuid: str
    username: str
    email: Optional[str]
    role: str
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


@router.get("/setup-status")
def check_setup_status(db: Session = Depends(get_db)):
    """Check if the system requires first-time administrator configuration."""
    admin_count = db.query(User).filter(User.role == "admin").count()
    return {"setup_needed": admin_count == 0}


@router.post("/setup", response_model=UserResponse)
def setup_initial_admin(req: SetupAdminRequest, request: Request, db: Session = Depends(get_db)):
    """
    First-time initial setup to configure the administrator account.
    Disabled once an admin exists. Never stores plaintext passwords.
    """
    if db.query(User).filter(User.role == "admin").count() > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System is already configured. Please log in with existing credentials."
        )

    admin = User(
        username=req.username.strip(),
        email=req.email,
        hashed_password=hash_password(req.password),
        role="admin",
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        actor=admin.username,
        actor_type="ADMIN",
        event="ADMIN_SETUP_INITIAL",
        ip_address=client_ip,
        status="SUCCESS",
        metadata={"email": req.email}
    )

    return admin


@router.post("/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate administrator with rate limiting and lockout protection."""
    client_ip = request.client.host if request.client else None
    user = authenticate_admin(db, req.username, req.password, client_ip=client_ip)

    access_token = create_access_token(data={"sub": user.username, "role": user.role, "id": user.id})

    log_audit_event(
        db=db,
        actor=user.username,
        actor_type="ADMIN",
        event="ADMIN_LOGIN",
        ip_address=client_ip,
        status="SUCCESS"
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        }
    }


@router.post("/logout")
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Log out current user and record audit entry."""
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="ADMIN_LOGOUT",
        ip_address=client_ip,
        status="SUCCESS"
    )
    return {"status": "success", "message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get profile of current authenticated user."""
    return current_user


@router.post("/change-password")
def change_password(req: ChangePasswordRequest, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Change password for current administrator."""
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password")

    current_user.hashed_password = hash_password(req.new_password)
    db.commit()

    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="PASSWORD_CHANGED",
        ip_address=client_ip,
        status="SUCCESS"
    )

    return {"status": "success", "message": "Password updated successfully"}
