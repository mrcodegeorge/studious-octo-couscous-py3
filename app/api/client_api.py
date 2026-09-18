import secrets
import string
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.config import settings
from app.models.device import Device
from app.models.device_registration import RegistrationCode, DeviceToken
from app.models.user import User
from app.services.authentication import get_current_user
from app.services.vendor_lookup import normalize_mac, lookup_vendor
from app.services.audit_service import log_audit_event, create_alert
from app.services.camera_manager import camera_manager
from app.websocket.manager import ws_manager
from app.websocket.events import SystemEvent, EventType

router = APIRouter(prefix="/api/client", tags=["Client"])


def utc_now():
    return datetime.now(timezone.utc)


def generate_formatted_code() -> str:
    """Generate a clean code: NET-XXXX-XXX."""
    chars = string.ascii_uppercase + string.digits
    chars = chars.replace("O", "").replace("0", "").replace("I", "").replace("1", "")
    p1 = "".join(secrets.choice(chars) for _ in range(4))
    p2 = "".join(secrets.choice(chars) for _ in range(3))
    return f"NET-{p1}-{p2}"


class ClientRegisterRequest(BaseModel):
    registration_code: str
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    client_version: Optional[str] = "1.0.0"


class HeartbeatRequest(BaseModel):
    client_version: Optional[str] = "1.0.0"


class PermissionResponseRequest(BaseModel):
    session_uuid: str
    allowed: bool


class ClientStopCameraRequest(BaseModel):
    session_uuid: str


# --- Admin Code Generation ---
@router.post("/generate-code")
def generate_registration_code(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Administrator generates an ephemeral single-use registration code."""
    code_str = generate_formatted_code()
    expires_at = utc_now() + timedelta(minutes=settings.REGISTRATION_CODE_EXPIRE_MINUTES)

    reg_code = RegistrationCode(
        code=code_str,
        created_by=current_user.username,
        expires_at=expires_at,
        is_used=False
    )
    db.add(reg_code)
    db.commit()
    db.refresh(reg_code)

    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="REGISTRATION_CODE_GENERATED",
        status="SUCCESS",
        metadata={"code": code_str, "expires_in_minutes": settings.REGISTRATION_CODE_EXPIRE_MINUTES}
    )

    return {
        "code": code_str,
        "expires_at": expires_at.isoformat(),
        "expires_in_minutes": settings.REGISTRATION_CODE_EXPIRE_MINUTES
    }


# --- Client Registration ---
@router.post("/register")
def register_client(req: ClientRegisterRequest, request: Request, db: Session = Depends(get_db)):
    """
    Enrolls a client device using an active, unexpired registration code.
    Generates a cryptographically strong client token and pairs the device.
    """
    now = utc_now()
    code_record = db.query(RegistrationCode).filter(
        RegistrationCode.code == req.registration_code.strip().upper(),
        RegistrationCode.is_used == False,
    ).first()

    if not code_record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid registration code")

    # Check expiration
    exp = code_record.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if now > exp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Registration code has expired")

    mac = normalize_mac(req.mac_address)
    if not mac:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MAC address format")

    # Find or create device record
    device = db.query(Device).filter(Device.mac_address == mac).first()
    if not device:
        device = Device(
            ip_address=req.ip_address,
            mac_address=mac,
            hostname=req.hostname,
            vendor=lookup_vendor(mac),
            first_seen=now,
            last_seen=now,
            status="ONLINE",
            trusted=True,  # Device registered with admin code is initially marked trusted
            client_registered=True,
            client_version=req.client_version,
        )
        db.add(device)
        db.commit()
        db.refresh(device)
    else:
        device.ip_address = req.ip_address
        if req.hostname:
            device.hostname = req.hostname
        device.last_seen = now
        device.status = "ONLINE"
        device.trusted = True
        device.client_registered = True
        device.client_version = req.client_version
        db.commit()

    # Mark code as used
    code_record.is_used = True
    code_record.used_at = now
    code_record.used_by_device_id = device.id
    db.commit()

    # Generate secure random client token
    raw_token = secrets.token_hex(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    device_token = DeviceToken(
        device_id=device.id,
        token_hash=token_hash,
        issued_at=now,
        last_used_at=now,
        is_revoked=False
    )
    db.add(device_token)
    db.commit()

    client_ip = request.client.host if request.client else req.ip_address
    log_audit_event(
        db=db,
        actor=f"Client ({device.hostname or device.ip_address})",
        actor_type="CLIENT",
        event="CLIENT_REGISTERED",
        device_id=device.id,
        device_name=device.hostname or device.ip_address,
        ip_address=client_ip,
        status="SUCCESS",
        metadata={"mac": mac, "version": req.client_version}
    )

    create_alert(
        db=db,
        alert_type="NEW_DEVICE",
        title="NETSENTRY Client Enrolled",
        message=f"Device {device.hostname or device.ip_address} has successfully enrolled with NETSENTRY.",
        severity="INFO",
        device_id=device.id
    )

    return {
        "status": "success",
        "device_uuid": device.device_uuid,
        "device_id": device.id,
        "client_token": raw_token,
        "server_time": now.isoformat()
    }


def verify_client_auth(
    x_device_uuid: str = Header(..., alias="X-Device-UUID"),
    x_client_token: str = Header(..., alias="X-Client-Token"),
    db: Session = Depends(get_db)
) -> Device:
    """Dependency to authenticate requests coming from an enrolled client."""
    device = db.query(Device).filter(Device.device_uuid == x_device_uuid).first()
    if not device or not device.client_registered:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device not registered or revoked")

    token_hash = hashlib.sha256(x_client_token.encode("utf-8")).hexdigest()
    token_entry = db.query(DeviceToken).filter(
        DeviceToken.device_id == device.id,
        DeviceToken.token_hash == token_hash,
        DeviceToken.is_revoked == False
    ).first()

    if not token_entry:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked client token")

    token_entry.last_used_at = utc_now()
    db.commit()
    return device


# --- Client Heartbeat ---
@router.post("/heartbeat")
def client_heartbeat(
    req: HeartbeatRequest,
    device: Device = Depends(verify_client_auth),
    db: Session = Depends(get_db)
):
    """Periodic client heartbeat verifying active status."""
    device.last_seen = utc_now()
    device.status = "ONLINE"
    device.client_version = req.client_version
    db.commit()
    return {"status": "ok", "timestamp": utc_now().isoformat()}


# --- Client Camera Permission Handshake ---
@router.post("/camera/permission")
async def client_camera_permission(
    req: PermissionResponseRequest,
    request: Request,
    device: Device = Depends(verify_client_auth)
):
    """
    Client reports explicit user decision (ALLOW or DENY).
    Camera starts ONLY if req.allowed is True.
    """
    client_ip = request.client.host if request.client else device.ip_address
    await camera_manager.handle_permission_response(
        session_uuid=req.session_uuid,
        device_uuid=device.device_uuid,
        approved=req.allowed,
        client_ip=client_ip
    )
    return {"status": "processed", "allowed": req.allowed}


# --- Client Camera Stop ---
@router.post("/camera/stop")
async def client_stop_camera(
    req: ClientStopCameraRequest,
    device: Device = Depends(verify_client_auth)
):
    """
    User clicks [STOP CAMERA] on their device, terminating the feed instantly.
    """
    session = await camera_manager.terminate_session(
        session_uuid=req.session_uuid,
        reason="USER_STOPPED",
        actor=f"Client ({device.hostname or device.ip_address})",
        actor_type="CLIENT"
    )
    if not session:
        raise HTTPException(status_code=404, detail="Active session not found")

    return {"status": "stopped", "session_uuid": req.session_uuid}
