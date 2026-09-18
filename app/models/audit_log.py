from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class AuditLog(Base):
    """
    Immutable audit log entry.
    Entries must never be updated or deleted by normal users or through the UI.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True, nullable=False)
    actor = Column(String(64), index=True, nullable=False)  # Admin username, Client UUID, System
    actor_type = Column(String(32), default="ADMIN", nullable=False)  # ADMIN, CLIENT, SYSTEM
    event = Column(String(64), index=True, nullable=False)  # ADMIN_LOGIN, DEVICE_DISCOVERED, CAMERA_REQUESTED, etc.
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    device_name = Column(String(128), nullable=True)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(32), default="SUCCESS", nullable=False)  # SUCCESS, FAILURE, DENIED
    metadata_json = Column(Text, nullable=True)  # JSON-encoded extra details
