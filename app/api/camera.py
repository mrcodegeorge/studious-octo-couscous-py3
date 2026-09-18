from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.user import User
from app.models.device import Device
from app.models.camera_session import CameraSession
from app.services.authentication import get_current_user
from app.services.camera_manager import camera_manager
from app.websocket.manager import ws_manager

router = APIRouter(prefix="/api/camera", tags=["Camera"])


class RequestCameraSessionPayload(BaseModel):
    purpose: str = Field(default="Authorized network monitoring/research", max_length=255)
    duration_minutes: Optional[int] = Field(default=10, ge=1, le=30)


class CameraSessionResponse(BaseModel):
    id: int
    session_uuid: str
    device_id: int
    device_name: Optional[str] = None
    device_ip: Optional[str] = None
    admin_username: str
    permission_status: str
    purpose: str
    max_duration_seconds: int
    requested_at: datetime
    approved_at: Optional[datetime]
    ended_at: Optional[datetime]
    session_duration_seconds: float
    termination_reason: Optional[str]
    is_stream_live: bool = False

    class Config:
        from_attributes = True


@router.post("/request/{device_id}", response_model=CameraSessionResponse)
async def request_camera_access(
    device_id: int,
    req: RequestCameraSessionPayload,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Administrator requests camera access for an enrolled client device.
    Camera remains completely OFF until the remote user explicitly clicks ALLOW.
    """
    client_ip = request.client.host if request.client else None
    try:
        session = await camera_manager.request_camera_access(
            db=db,
            device_id=device_id,
            admin_id=current_user.id,
            admin_username=current_user.username,
            purpose=req.purpose,
            duration_minutes=req.duration_minutes,
            admin_ip=client_ip
        )
        device = db.query(Device).filter(Device.id == device_id).first()

        resp = CameraSessionResponse.from_orm(session)
        resp.device_name = device.hostname if device else "Unknown"
        resp.device_ip = device.ip_address if device else "Unknown"
        return resp
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{session_uuid}/terminate")
async def terminate_camera_session(
    session_uuid: str,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Administrator immediately terminates an active or requested camera session."""
    session = await camera_manager.terminate_session(
        session_uuid=session_uuid,
        reason="ADMIN_STOPPED",
        actor=current_user.username,
        actor_type="ADMIN"
    )
    if not session:
        raise HTTPException(status_code=404, detail="Camera session not found")

    return {"status": "terminated", "session_uuid": session_uuid, "duration_seconds": session.session_duration_seconds}


@router.get("/sessions", response_model=List[CameraSessionResponse])
def list_camera_sessions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List historical and active camera sessions."""
    sessions = db.query(CameraSession).order_by(CameraSession.requested_at.desc()).limit(100).all()
    results = []
    for s in sessions:
        device = db.query(Device).filter(Device.id == s.device_id).first()
        resp = CameraSessionResponse.from_orm(s)
        resp.device_name = device.hostname if device else "Unknown"
        resp.device_ip = device.ip_address if device else "Unknown"
        resp.is_stream_live = (s.session_uuid in ws_manager.stream_producers)
        results.append(resp)
    return results


@router.get("/sessions/{session_uuid}", response_model=CameraSessionResponse)
def get_camera_session(session_uuid: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get single camera session details."""
    session = db.query(CameraSession).filter(CameraSession.session_uuid == session_uuid).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    device = db.query(Device).filter(Device.id == session.device_id).first()
    resp = CameraSessionResponse.from_orm(session)
    resp.device_name = device.hostname if device else "Unknown"
    resp.device_ip = device.ip_address if device else "Unknown"
    resp.is_stream_live = (session.session_uuid in ws_manager.stream_producers)
    return resp
