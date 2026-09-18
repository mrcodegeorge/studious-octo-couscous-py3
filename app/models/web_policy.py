import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.database import Base


class WebFilterRule(Base):
    """
    Defines domain or hostname filter patterns enforced on monitored clients.
    """
    __tablename__ = "web_filter_rules"

    id = Column(Integer, primary_key=True, index=True)
    domain_pattern = Column(String(255), nullable=False, unique=True, index=True)  # e.g. "facebook.com", "*.tiktok.com", "*gambling*"
    category = Column(String(50), default="General")  # Social Media, Streaming, Gaming, Adult, VPN/Proxy, Custom
    action = Column(String(20), default="BLOCK")  # BLOCK, ALERT
    description = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class WebActivityLog(Base):
    """
    Log of network endpoints and domains accessed by client devices.
    """
    __tablename__ = "web_activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    mac_address = Column(String(32), nullable=True, index=True)
    ip_address = Column(String(64), nullable=True)
    domain = Column(String(255), nullable=False, index=True)
    remote_ip = Column(String(64), nullable=True)
    process_name = Column(String(100), nullable=True)  # e.g. "chrome.exe", "msedge.exe"
    action_taken = Column(String(20), default="ALLOWED")  # ALLOWED, BLOCKED, FLAG
    category = Column(String(50), nullable=True)
    matched_rule = Column(String(255), nullable=True)
    is_vpn_traffic = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    device = relationship("Device", backref="web_activities")


class VpnRestrictionPolicy(Base):
    """
    Policy controlling whether VPN tunnel adapters are permitted on client nodes.
    """
    __tablename__ = "vpn_restriction_policies"

    id = Column(Integer, primary_key=True, index=True)
    block_all_vpns = Column(Boolean, default=True)
    block_wireguard = Column(Boolean, default=True)
    block_openvpn = Column(Boolean, default=True)
    terminate_vpn_processes = Column(Boolean, default=True)
    custom_blocked_adapters = Column(Text, nullable=True)  # Comma-separated adapter name substrings
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)
