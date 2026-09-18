import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class CameraSession(Base):
    __tablename__ = "camera_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    admin_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    admin_username = Column(String(64), nullable=False)
    
    # State: REQUESTED, APPROVED, DENIED, ACTIVE, TERMINATED, EXPIRED
    permission_status = Column(String(32), default="REQUESTED", nullable=False)
    
    purpose = Column(String(255), default="Authorized network monitoring/research", nullable=False)
    max_duration_seconds = Column(Integer, default=600, nullable=False)  # 10 minutes default
    
    requested_at = Column(DateTime, default=utc_now, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    denied_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    
    session_duration_seconds = Column(Float, default=0.0, nullable=False)
    
    # Termination reason: USER_STOPPED, ADMIN_STOPPED, TIMEOUT, CLIENT_DISCONNECTED, ERROR, DENIED
    termination_reason = Column(String(64), nullable=True)
    
    client_ip = Column(String(45), nullable=True)
    admin_ip = Column(String(45), nullable=True)
    
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    device = relationship("Device", back_populates="camera_sessions")
    admin = relationship("User")
