from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.device import Device
from app.models.camera_session import CameraSession
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.authentication import get_current_user
from app.services.audit_service import log_audit_event
from app.websocket.manager import ws_manager

router = APIRouter(prefix="/api/devices", tags=["Devices"])


class DeviceResponse(BaseModel):
    id: int
    device_uuid: str
    ip_address: str
    mac_address: str
    hostname: Optional[str]
    vendor: Optional[str]
    first_seen: datetime
    last_seen: datetime
    status: str
    trusted: bool
    trusted_at: Optional[datetime]
    trusted_by: Optional[str]
    client_registered: bool
    client_version: Optional[str]
    client_connected: bool = False
    active_camera_session: bool = False
    response_time_ms: Optional[float]
    custom_label: Optional[str]

    class Config:
        from_attributes = True


class UpdateDeviceLabelRequest(BaseModel):
    custom_label: str


@router.get("", response_model=List[DeviceResponse])
def get_devices(
    status_filter: Optional[str] = Query(None, alias="status"),
    trusted_filter: Optional[bool] = Query(None, alias="trusted"),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all discovered and registered network devices with real-time connection flags."""
    query = db.query(Device)

    if status_filter:
        query = query.filter(Device.status == status_filter.upper())
    if trusted_filter is not None:
        query = query.filter(Device.trusted == trusted_filter)
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (Device.ip_address.like(search_term)) |
            (Device.mac_address.like(search_term)) |
            (Device.hostname.like(search_term)) |
            (Device.vendor.like(search_term)) |
            (Device.custom_label.like(search_term))
        )

    devices = query.order_by(Device.last_seen.desc()).all()

    # Query any active camera sessions
    active_device_ids = set(
        s[0] for s in db.query(CameraSession.device_id).filter(
            CameraSession.permission_status.in_(["REQUESTED", "APPROVED", "ACTIVE"])
        ).all()
    )

    results = []
    for d in devices:
        resp = DeviceResponse.from_orm(d)
        resp.client_connected = ws_manager.is_client_connected(d.device_uuid)
        resp.active_camera_session = d.id in active_device_ids
        results.append(resp)

    return results


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Summary KPI metrics for the administrator dashboard."""
    total = db.query(Device).count()
    online = db.query(Device).filter(Device.status == "ONLINE").count()
    offline = db.query(Device).filter(Device.status == "OFFLINE").count()
    trusted = db.query(Device).filter(Device.trusted == True).count()
    new_devices = db.query(Device).filter(Device.status == "NEW").count()
    clients = db.query(Device).filter(Device.client_registered == True).count()
    active_camera_sessions = db.query(CameraSession).filter(
        CameraSession.permission_status.in_(["REQUESTED", "APPROVED", "ACTIVE"])
    ).count()

    return {
        "total_devices": total,
        "online_devices": online,
        "offline_devices": offline,
        "trusted_devices": trusted,
        "new_devices": new_devices,
        "camera_capable_clients": clients,
        "active_camera_sessions": active_camera_sessions,
    }


@router.get("/{device_id}")
def get_device_detail(device_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieve detailed device information and connection/audit timeline."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    resp = DeviceResponse.from_orm(device)
    resp.client_connected = ws_manager.is_client_connected(device.device_uuid)
    resp.active_camera_session = db.query(CameraSession).filter(
        CameraSession.device_id == device.id,
        CameraSession.permission_status.in_(["REQUESTED", "APPROVED", "ACTIVE"])
    ).first() is not None

    # Fetch device timeline events from AuditLogs
    timeline_logs = db.query(AuditLog).filter(
        AuditLog.device_id == device.id
    ).order_by(AuditLog.timestamp.desc()).limit(50).all()

    timeline = []
    for log in timeline_logs:
        timeline.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "event": log.event,
            "actor": log.actor,
            "actor_type": log.actor_type,
            "status": log.status,
            "metadata": log.metadata_json
        })

    # Recent camera sessions
    sessions = db.query(CameraSession).filter(
        CameraSession.device_id == device.id
    ).order_by(CameraSession.requested_at.desc()).limit(10).all()

    camera_history = []
    for s in sessions:
        camera_history.append({
            "session_uuid": s.session_uuid,
            "admin_username": s.admin_username,
            "permission_status": s.permission_status,
            "requested_at": s.requested_at.isoformat(),
            "approved_at": s.approved_at.isoformat() if s.approved_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            "duration_seconds": s.session_duration_seconds,
            "termination_reason": s.termination_reason,
        })

    return {
        "device": resp,
        "timeline": timeline,
        "camera_history": camera_history,
    }


@router.post("/{device_id}/trust")
def set_device_trust(
    device_id: int,
    trusted: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark a device as trusted or remove trust status."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.trusted = trusted
    device.trusted_at = datetime.now(timezone.utc) if trusted else None
    device.trusted_by = current_user.username if trusted else None
    db.commit()

    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="DEVICE_TRUST_GRANTED" if trusted else "DEVICE_TRUST_REVOKED",
        device_id=device.id,
        device_name=device.hostname or device.ip_address,
        status="SUCCESS",
        metadata={"trusted": trusted}
    )

    return {"status": "success", "trusted": device.trusted}


@router.delete("/{device_id}/trust")
def remove_device_trust(device_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Convenience DELETE endpoint to untrust a device."""
    return set_device_trust(device_id, trusted=False, db=db, current_user=current_user)


@router.post("/{device_id}/label")
def update_device_label(
    device_id: int,
    req: UpdateDeviceLabelRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Assign a human-friendly label/alias to a device."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.custom_label = req.custom_label.strip()
    db.commit()
    return {"status": "success", "custom_label": device.custom_label}


@router.post("/{device_id}/revoke-client")
def revoke_client_registration(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Revoke NETSENTRY client enrollment for a device."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    device.client_registered = False
    device.client_version = None
    db.commit()

    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="CLIENT_REGISTRATION_REVOKED",
        device_id=device.id,
        device_name=device.hostname or device.ip_address,
        status="SUCCESS"
    )

    return {"status": "success", "message": "Client registration revoked"}
