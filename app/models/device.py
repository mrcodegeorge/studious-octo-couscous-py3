import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from sqlalchemy.orm import relationship
from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    device_uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    ip_address = Column(String(45), index=True, nullable=False)
    mac_address = Column(String(17), unique=True, index=True, nullable=False)
    hostname = Column(String(128), nullable=True)
    vendor = Column(String(128), nullable=True)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)
    status = Column(String(32), default="ONLINE", nullable=False)  # ONLINE, OFFLINE, NEW, UNKNOWN
    trusted = Column(Boolean, default=False, nullable=False)
    trusted_at = Column(DateTime, nullable=True)
    trusted_by = Column(String(64), nullable=True)
    client_registered = Column(Boolean, default=False, nullable=False)
    client_version = Column(String(32), nullable=True)
    response_time_ms = Column(Float, nullable=True)
    custom_label = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    camera_sessions = relationship("CameraSession", back_populates="device", cascade="all, delete-orphan")
    tokens = relationship("DeviceToken", back_populates="device", cascade="all, delete-orphan")
