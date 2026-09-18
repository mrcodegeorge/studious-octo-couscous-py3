import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.config import settings
from app.database.database import SessionLocal
from app.models.device import Device
from app.models.camera_session import CameraSession
from app.services.audit_service import log_audit_event, create_alert
from app.websocket.manager import ws_manager
from app.websocket.events import SystemEvent, EventType

logger = logging.getLogger(__name__)


def utc_now():
    return datetime.now(timezone.utc)


class CameraManager:
    def __init__(self):
        # In-memory registry of active session timeouts: {session_uuid: asyncio.Task}
        self.session_timers: Dict[str, asyncio.Task] = {}

    async def request_camera_access(
        self,
        db: Session,
        device_id: int,
        admin_id: int,
        admin_username: str,
        purpose: str = "Authorized network monitoring/research",
        duration_minutes: Optional[int] = None,
        admin_ip: Optional[str] = None
    ) -> CameraSession:
        """
        Administrator initiates a consent-based camera request.
        The camera will NOT start until the device owner explicitly approves.
        """
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError("Target device not found")

        if not device.client_registered:
            raise ValueError("Device does not have an enrolled NETSENTRY client")

        if not ws_manager.is_client_connected(device.device_uuid):
            raise ValueError("NETSENTRY client is currently offline or unreachable")

        # Check for already active session on this device
        active_session = db.query(CameraSession).filter(
            CameraSession.device_id == device_id,
            CameraSession.permission_status.in_(["REQUESTED", "APPROVED", "ACTIVE"])
        ).first()
        if active_session:
            raise ValueError("An active or pending camera session already exists for this device")

        max_minutes = duration_minutes or settings.CAMERA_SESSION_MAX_MINUTES
        max_minutes = min(max(1, max_minutes), 30)  # Bound between 1 and 30 minutes
        max_duration_seconds = max_minutes * 60

        # Create session record with REQUESTED status
        session = CameraSession(
            device_id=device_id,
            admin_id=admin_id,
            admin_username=admin_username,
            permission_status="REQUESTED",
            purpose=purpose,
            max_duration_seconds=max_duration_seconds,
            requested_at=utc_now(),
            admin_ip=admin_ip,
            client_ip=device.ip_address,
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        # Audit log for camera request
        log_audit_event(
            db=db,
            actor=admin_username,
            actor_type="ADMIN",
            event="CAMERA_REQUESTED",
            device_id=device.id,
            device_name=device.hostname or device.ip_address,
            ip_address=admin_ip,
            status="SUCCESS",
            metadata={
                "session_uuid": session.session_uuid,
                "purpose": purpose,
                "max_duration_minutes": max_minutes
            }
        )

        # Dispatch permission request message directly to the target client over WebSocket
        sent = await ws_manager.send_to_client(
            device.device_uuid,
            {
                "type": "CAMERA_PERMISSION_PROMPT",
                "session_uuid": session.session_uuid,
                "admin_username": admin_username,
                "purpose": purpose,
                "duration_minutes": max_minutes,
                "timestamp": utc_now().isoformat(),
            }
        )

        if not sent:
            session.permission_status = "TERMINATED"
            session.termination_reason = "CLIENT_UNREACHABLE"
            session.ended_at = utc_now()
            db.commit()
            raise ValueError("Failed to deliver permission request to client")

        # Broadcast event to dashboard
        await ws_manager.broadcast_event(
            SystemEvent.create(
                event_type=EventType.CAMERA_REQUESTED,
                data={
                    "session_uuid": session.session_uuid,
                    "device_id": device.id,
                    "device_name": device.hostname or device.ip_address,
                    "admin_username": admin_username,
                    "purpose": purpose,
                    "status": "REQUESTED"
                },
                message=f"Camera access requested for {device.hostname or device.ip_address}"
            )
        )

        # Start a 60-second timer to expire prompt if user doesn't answer
        self.session_timers[session.session_uuid] = asyncio.create_task(
            self._prompt_timeout_guard(session.session_uuid, timeout_seconds=60)
        )

        return session

    async def handle_permission_response(
        self,
        session_uuid: str,
        device_uuid: str,
        approved: bool,
        client_ip: Optional[str] = None
    ):
        """
        Handle the user's explicit consent decision from the client application.
        """
        db: Session = SessionLocal()
        try:
            session = db.query(CameraSession).filter(CameraSession.session_uuid == session_uuid).first()
            if not session or session.permission_status != "REQUESTED":
                logger.warning(f"Invalid or expired session {session_uuid} for permission response")
                return

            device = db.query(Device).filter(Device.id == session.device_id).first()
            now = utc_now()

            # Cancel prompt timeout guard
            if session_uuid in self.session_timers:
                self.session_timers[session_uuid].cancel()
                del self.session_timers[session_uuid]

            if approved:
                # User clicked ALLOW
                session.permission_status = "APPROVED"
                session.approved_at = now
                session.started_at = now
                db.commit()

                log_audit_event(
                    db=db,
                    actor=f"Client ({device.hostname or device.ip_address})",
                    actor_type="CLIENT",
                    event="CAMERA_APPROVED",
                    device_id=device.id,
                    device_name=device.hostname or device.ip_address,
                    ip_address=client_ip,
                    status="SUCCESS",
                    metadata={"session_uuid": session_uuid}
                )

                log_audit_event(
                    db=db,
                    actor=session.admin_username,
                    actor_type="ADMIN",
                    event="CAMERA_STARTED",
                    device_id=device.id,
                    device_name=device.hostname or device.ip_address,
                    ip_address=client_ip,
                    status="SUCCESS",
                    metadata={"session_uuid": session_uuid}
                )

                create_alert(
                    db=db,
                    alert_type="CAMERA_STARTED",
                    title="Camera Session Started",
                    message=f"Camera session {session_uuid[:8]} is active on {device.hostname or device.ip_address} with consent.",
                    severity="INFO",
                    device_id=device.id
                )

                # Broadcast events
                await ws_manager.broadcast_event(
                    SystemEvent.create(
                        event_type=EventType.CAMERA_APPROVED,
                        data={"session_uuid": session_uuid, "device_id": device.id, "status": "APPROVED"},
                        message="Camera permission granted by user"
                    )
                )
                await ws_manager.broadcast_event(
                    SystemEvent.create(
                        event_type=EventType.CAMERA_STARTED,
                        data={
                            "session_uuid": session_uuid,
                            "device_id": device.id,
                            "max_duration_seconds": session.max_duration_seconds,
                            "started_at": now.isoformat()
                        },
                        message="Camera stream started"
                    )
                )

                # Start session expiration timer task
                self.session_timers[session_uuid] = asyncio.create_task(
                    self._session_expiration_guard(session_uuid, session.max_duration_seconds)
                )

            else:
                # User clicked DENY
                session.permission_status = "DENIED"
                session.denied_at = now
                session.ended_at = now
                session.termination_reason = "DENIED_BY_USER"
                db.commit()

                log_audit_event(
                    db=db,
                    actor=f"Client ({device.hostname or device.ip_address})",
                    actor_type="CLIENT",
                    event="CAMERA_DENIED",
                    device_id=device.id,
                    device_name=device.hostname or device.ip_address,
                    ip_address=client_ip,
                    status="DENIED",
                    metadata={"session_uuid": session_uuid}
                )

                create_alert(
                    db=db,
                    alert_type="CAMERA_DENIED",
                    title="Camera Access Denied",
                    message=f"User on {device.hostname or device.ip_address} explicitly denied camera access.",
                    severity="WARNING",
                    device_id=device.id
                )

                await ws_manager.broadcast_event(
                    SystemEvent.create(
                        event_type=EventType.CAMERA_DENIED,
                        data={"session_uuid": session_uuid, "device_id": device.id, "status": "DENIED"},
                        message="Camera permission DENIED by user"
                    )
                )
        finally:
            db.close()

    async def terminate_session(
        self,
        session_uuid: str,
        reason: str = "ADMIN_STOPPED",
        actor: str = "Admin",
        actor_type: str = "ADMIN"
    ) -> Optional[CameraSession]:
        """
        Terminate an active or requested camera session immediately.
        Can be triggered by admin, user, timeout, or disconnect.
        """
        db: Session = SessionLocal()
        try:
            session = db.query(CameraSession).filter(CameraSession.session_uuid == session_uuid).first()
            if not session:
                return None

            if session.permission_status in ["TERMINATED", "EXPIRED", "DENIED"]:
                return session

            now = utc_now()
            duration = 0.0
            if session.started_at:
                started = session.started_at
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                duration = round((now - started).total_seconds(), 2)

            session.permission_status = "EXPIRED" if reason == "TIMEOUT" else "TERMINATED"
            session.ended_at = now
            session.session_duration_seconds = duration
            session.termination_reason = reason
            db.commit()

            device = db.query(Device).filter(Device.id == session.device_id).first()
            dev_name = (device.hostname or device.ip_address) if device else "Unknown"

            # Cancel running timer if any
            if session_uuid in self.session_timers:
                self.session_timers[session_uuid].cancel()
                del self.session_timers[session_uuid]

            # Signal client to stop camera hardware if it was active
            if device:
                await ws_manager.send_to_client(
                    device.device_uuid,
                    {"type": "CAMERA_STOP_COMMAND", "session_uuid": session_uuid, "reason": reason}
                )

            # Audit log
            log_audit_event(
                db=db,
                actor=actor,
                actor_type=actor_type,
                event="CAMERA_STOPPED",
                device_id=session.device_id,
                device_name=dev_name,
                status="SUCCESS",
                metadata={"session_uuid": session_uuid, "reason": reason, "duration_seconds": duration}
            )

            # Create alert
            create_alert(
                db=db,
                alert_type="CAMERA_STOPPED",
                title="Camera Session Terminated",
                message=f"Camera session {session_uuid[:8]} ended. Reason: {reason}. Duration: {duration}s.",
                severity="INFO",
                device_id=session.device_id
            )

            # Broadcast event
            await ws_manager.broadcast_event(
                SystemEvent.create(
                    event_type=EventType.CAMERA_STOPPED,
                    data={
                        "session_uuid": session_uuid,
                        "device_id": session.device_id,
                        "reason": reason,
                        "duration_seconds": duration
                    },
                    message=f"Camera session stopped ({reason})"
                )
            )

            return session
        finally:
            db.close()

    async def _prompt_timeout_guard(self, session_uuid: str, timeout_seconds: int = 60):
        """If user ignores permission prompt for 60 seconds, auto-expire request."""
        try:
            await asyncio.sleep(timeout_seconds)
            await self.terminate_session(session_uuid, reason="PROMPT_TIMEOUT", actor="System", actor_type="SYSTEM")
        except asyncio.CancelledError:
            pass

    async def _session_expiration_guard(self, session_uuid: str, duration_seconds: int):
        """Ensure session automatically terminates when maximum allowed duration is reached."""
        try:
            await asyncio.sleep(duration_seconds)
            await self.terminate_session(session_uuid, reason="TIMEOUT", actor="System", actor_type="SYSTEM")
        except asyncio.CancelledError:
            pass


camera_manager = CameraManager()
