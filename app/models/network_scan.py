from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class NetworkScan(Base):
    __tablename__ = "network_scans"

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    interface = Column(String(64), nullable=True)
    subnet = Column(String(64), nullable=False)
    devices_found = Column(Integer, default=0, nullable=False)
    new_devices = Column(Integer, default=0, nullable=False)
    scan_type = Column(String(32), default="ARP", nullable=False)  # ARP, ICMP, DEMO
    status = Column(String(32), default="RUNNING", nullable=False)  # RUNNING, COMPLETED, FAILED
    error_message = Column(Text, nullable=True)
