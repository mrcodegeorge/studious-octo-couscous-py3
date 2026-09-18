import json
import logging
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.models.alert import Alert

logger = logging.getLogger(__name__)


def log_audit_event(
    db: Session,
    actor: str,
    event: str,
    actor_type: str = "ADMIN",
    device_id: Optional[int] = None,
    device_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "SUCCESS",
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Append an immutable audit entry to the audit trail.
    Ensures critical actions are permanently recorded with full context.
    """
    try:
        metadata_str = json.dumps(metadata) if metadata else None
        audit_entry = AuditLog(
            actor=actor,
            actor_type=actor_type,
            event=event,
            device_id=device_id,
            device_name=device_name,
            ip_address=ip_address,
            status=status,
            metadata_json=metadata_str,
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        logger.info(f"[AUDIT] {event} by {actor} ({status}) - Device: {device_name or device_id} - IP: {ip_address}")
        return audit_entry
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to record audit event: {e}")
        raise


def create_alert(
    db: Session,
    alert_type: str,
    title: str,
    message: str,
    severity: str = "INFO",
    device_id: Optional[int] = None,
) -> Alert:
    """Create a new system/security alert."""
    try:
        alert = Alert(
            alert_type=alert_type,
            title=title,
            message=message,
            severity=severity,
            device_id=device_id,
            is_read=False,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        logger.info(f"[ALERT] [{severity}] {title}: {message}")
        return alert
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create alert: {e}")
        raise
