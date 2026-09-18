import socket
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.models.user import User
from app.models.network_scan import NetworkScan
from app.services.authentication import get_current_user
from app.services.network_scanner import scanner, get_default_local_ip
from app.services.device_monitor import device_monitor
from app.services.audit_service import log_audit_event
from app.config import settings

router = APIRouter(prefix="/api/network", tags=["Network"])


class UpdateSubnetRequest(BaseModel):
    subnet: str


class DemoModeRequest(BaseModel):
    enabled: bool


@router.get("/status")
def get_network_status(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Return local interface, subnet, scanner state, and background monitoring status."""
    local_ip, auto_subnet = get_default_local_ip()
    hostname = socket.gethostname()

    last_scan = db.query(NetworkScan).order_by(NetworkScan.started_at.desc()).first()

    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "authorized_subnet": scanner.subnet_cidr,
        "auto_detected_subnet": auto_subnet,
        "interface": settings.NETWORK_INTERFACE or "Auto-detected Default Interface",
        "is_scanning": scanner.is_scanning,
        "monitoring_active": device_monitor.is_running,
        "scan_interval_seconds": device_monitor.interval,
        "demo_mode": settings.DEMO_MODE,
        "last_scan": {
            "started_at": last_scan.started_at.isoformat() if last_scan else None,
            "duration_seconds": last_scan.duration_seconds if last_scan else None,
            "devices_found": last_scan.devices_found if last_scan else 0,
            "status": last_scan.status if last_scan else "NEVER_RUN"
        } if last_scan else None
    }


@router.post("/scan")
async def trigger_manual_scan(request: Request, current_user: User = Depends(get_current_user)):
    """Trigger an on-demand authorized network scan."""
    if scanner.is_scanning:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A scan is already in progress. Please wait.")

    client_ip = request.client.host if request.client else None
    res = await device_monitor.trigger_single_scan()
    return res


@router.post("/monitor/start")
async def start_background_monitoring(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Start periodic background network discovery."""
    if device_monitor.is_running:
        return {"status": "already_running", "interval": device_monitor.interval}

    await device_monitor.start()

    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="NETWORK_MONITOR_STARTED",
        ip_address=client_ip,
        status="SUCCESS",
        metadata={"interval": device_monitor.interval}
    )

    return {"status": "started", "interval": device_monitor.interval}


@router.post("/monitor/stop")
async def stop_background_monitoring(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Stop periodic background network discovery."""
    await device_monitor.stop()

    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="NETWORK_MONITOR_STOPPED",
        ip_address=client_ip,
        status="SUCCESS"
    )

    return {"status": "stopped"}


@router.post("/subnet")
def update_authorized_subnet(
    req: UpdateSubnetRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update authorized scanning subnet CIDR."""
    subnet_str = req.subnet.strip()
    scanner.subnet_cidr = subnet_str
    settings.AUTHORIZED_SUBNET = subnet_str

    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="SUBNET_CONFIG_UPDATED",
        status="SUCCESS",
        metadata={"new_subnet": subnet_str}
    )

    return {"status": "success", "authorized_subnet": scanner.subnet_cidr}


@router.post("/demo-mode")
def toggle_demo_mode(
    req: DemoModeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Toggle Demonstration Simulation Mode."""
    settings.DEMO_MODE = req.enabled

    log_audit_event(
        db=db,
        actor=current_user.username,
        actor_type="ADMIN",
        event="DEMO_MODE_TOGGLED",
        status="SUCCESS",
        metadata={"demo_mode": settings.DEMO_MODE}
    )

    return {"status": "success", "demo_mode": settings.DEMO_MODE}
