from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, Response, HTTPException
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.device import Device
from app.models.camera_session import CameraSession
from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.authentication import get_current_user
from app.services.report_service import (
    generate_devices_pdf,
    generate_camera_sessions_pdf,
    generate_devices_csv,
    generate_audit_csv
)

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/devices")
def export_devices_report(
    format: str = Query("pdf", regex="^(pdf|csv)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export Network Device Inventory as PDF or CSV."""
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format == "pdf":
        pdf_buffer = generate_devices_pdf(devices, current_user.username)
        return Response(
            content=pdf_buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=netsentry_devices_{timestamp_slug}.pdf"}
        )
    else:
        csv_stream = generate_devices_csv(devices)
        return Response(
            content=csv_stream.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=netsentry_devices_{timestamp_slug}.csv"}
        )


@router.get("/camera")
def export_camera_report(
    format: str = Query("pdf", regex="^(pdf|csv)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export Consent-Based Camera Access & Session Report as PDF or CSV."""
    sessions = db.query(CameraSession).order_by(CameraSession.requested_at.desc()).all()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format == "pdf":
        pdf_buffer = generate_camera_sessions_pdf(sessions, current_user.username)
        return Response(
            content=pdf_buffer.getvalue(),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=netsentry_camera_sessions_{timestamp_slug}.pdf"}
        )
    else:
        import io, csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Session UUID", "Device ID", "Admin", "Status", "Purpose", "Requested At", "Approved At", "Ended At", "Duration (s)", "Reason"])
        for s in sessions:
            writer.writerow([
                s.id, s.session_uuid, s.device_id, s.admin_username, s.permission_status,
                s.purpose, s.requested_at.isoformat(),
                s.approved_at.isoformat() if s.approved_at else "",
                s.ended_at.isoformat() if s.ended_at else "",
                s.session_duration_seconds, s.termination_reason or ""
            ])
        output.seek(0)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=netsentry_camera_sessions_{timestamp_slug}.csv"}
        )


@router.get("/audit")
def export_audit_report(
    format: str = Query("csv", regex="^(csv)$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export Security Audit Logs as CSV."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    csv_stream = generate_audit_csv(logs)
    return Response(
        content=csv_stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=netsentry_audit_{timestamp_slug}.csv"}
    )
