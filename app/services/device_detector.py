import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models.device import Device
from app.services.audit_service import log_audit_event, create_alert
from app.websocket.manager import ws_manager
from app.websocket.events import SystemEvent, EventType

logger = logging.getLogger(__name__)


def utc_now():
    return datetime.now(timezone.utc)


async def process_scan_results(db: Session, scanned_devices: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Process raw network scan results against the device database.
    Updates existing records, classifies new devices, issues alerts,
    and broadcasts real-time events over WebSockets.
    """
    now = utc_now()
    scanned_macs = set()
    new_count = 0
    updated_count = 0

    for dev_info in scanned_devices:
        mac = dev_info["mac_address"]
        ip = dev_info["ip_address"]
        hostname = dev_info.get("hostname")
        vendor = dev_info.get("vendor", "Unknown")
        rtt = dev_info.get("response_time_ms")
        scanned_macs.add(mac)

        existing = db.query(Device).filter(Device.mac_address == mac).first()

        if not existing:
            # First time seeing this device
            new_dev = Device(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                first_seen=now,
                last_seen=now,
                status="NEW",
                trusted=False,
                client_registered=False,
                response_time_ms=rtt,
            )
            db.add(new_dev)
            db.commit()
            db.refresh(new_dev)
            new_count += 1

            # Log audit event
            log_audit_event(
                db=db,
                actor="System Scanner",
                actor_type="SYSTEM",
                event="DEVICE_DISCOVERED",
                device_id=new_dev.id,
                device_name=hostname or ip,
                ip_address=ip,
                status="SUCCESS",
                metadata={"mac": mac, "vendor": vendor}
            )

            # Generate security alert
            create_alert(
                db=db,
                alert_type="NEW_DEVICE",
                title="New Device Discovered",
                message=f"New device detected: {hostname or 'Unknown'} at {ip} ({vendor}, MAC: {mac})",
                severity="WARNING" if not new_dev.trusted else "INFO",
                device_id=new_dev.id
            )

            # Broadcast WebSocket event
            event = SystemEvent.create(
                event_type=EventType.DEVICE_DISCOVERED,
                data={
                    "id": new_dev.id,
                    "uuid": new_dev.device_uuid,
                    "ip_address": new_dev.ip_address,
                    "mac_address": new_dev.mac_address,
                    "hostname": new_dev.hostname,
                    "vendor": new_dev.vendor,
                    "status": new_dev.status,
                    "trusted": new_dev.trusted,
                    "client_registered": new_dev.client_registered,
                    "last_seen": new_dev.last_seen.isoformat(),
                },
                message=f"New device {ip} discovered"
            )
            await ws_manager.broadcast_event(event)

        else:
            # Device already known - check state transition
            was_offline = existing.status == "OFFLINE"
            existing.ip_address = ip
            if hostname:
                existing.hostname = hostname
            if vendor and vendor != "Unknown Device":
                existing.vendor = vendor
            existing.last_seen = now
            existing.response_time_ms = rtt

            if was_offline:
                existing.status = "ONLINE"
                db.commit()

                # Audit & alert for reconnection
                log_audit_event(
                    db=db,
                    actor="System Scanner",
                    actor_type="SYSTEM",
                    event="DEVICE_ONLINE",
                    device_id=existing.id,
                    device_name=existing.hostname or existing.ip_address,
                    ip_address=ip,
                    status="SUCCESS"
                )
                create_alert(
                    db=db,
                    alert_type="DEVICE_RECONNECT",
                    title="Device Reconnected",
                    message=f"Device {existing.hostname or existing.ip_address} has reconnected to the network.",
                    severity="INFO",
                    device_id=existing.id
                )
                event = SystemEvent.create(
                    event_type=EventType.DEVICE_ONLINE,
                    data={"id": existing.id, "uuid": existing.device_uuid, "status": "ONLINE", "ip": ip},
                    message=f"Device {ip} is now ONLINE"
                )
                await ws_manager.broadcast_event(event)
            else:
                # Normal refresh
                if existing.status == "NEW":
                    existing.status = "ONLINE"
                db.commit()
                updated_count += 1

    # Check for devices that went offline (not seen in last 45 seconds and currently marked ONLINE)
    offline_threshold = now - timedelta(seconds=45)
    offline_devices = db.query(Device).filter(
        Device.status == "ONLINE",
        Device.last_seen < offline_threshold
    ).all()

    for off_dev in offline_devices:
        off_dev.status = "OFFLINE"
        db.commit()

        log_audit_event(
            db=db,
            actor="System Scanner",
            actor_type="SYSTEM",
            event="DEVICE_OFFLINE",
            device_id=off_dev.id,
            device_name=off_dev.hostname or off_dev.ip_address,
            ip_address=off_dev.ip_address,
            status="SUCCESS"
        )
        create_alert(
            db=db,
            alert_type="DEVICE_OFFLINE",
            title="Device Offline",
            message=f"Device {off_dev.hostname or off_dev.ip_address} is no longer responding.",
            severity="WARNING",
            device_id=off_dev.id
        )
        event = SystemEvent.create(
            event_type=EventType.DEVICE_OFFLINE,
            data={"id": off_dev.id, "uuid": off_dev.device_uuid, "status": "OFFLINE"},
            message=f"Device {off_dev.ip_address} went OFFLINE"
        )
        await ws_manager.broadcast_event(event)

    return {"new": new_count, "updated": updated_count, "offline": len(offline_devices)}
