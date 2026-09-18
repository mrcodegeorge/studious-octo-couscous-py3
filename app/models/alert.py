from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    # Types: NEW_DEVICE, UNKNOWN_DEVICE, DEVICE_OFFLINE, DEVICE_RECONNECT, 
    # CAMERA_DENIED, CAMERA_STARTED, CAMERA_STOPPED, CLIENT_DISCONNECTED
    alert_type = Column(String(64), index=True, nullable=False)
    # Severity: INFO, WARNING, CRITICAL
    severity = Column(String(16), default="INFO", nullable=False)
    title = Column(String(128), nullable=False)
    message = Column(Text, nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utc_now, index=True, nullable=False)

    device = relationship("Device")
