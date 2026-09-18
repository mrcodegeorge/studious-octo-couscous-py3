import logging
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from app.websocket.manager import ws_manager
from app.services.authentication import verify_access_token
from app.database.database import SessionLocal
from app.models.camera_session import CameraSession
from app.models.device import Device
from app.services.camera_manager import camera_manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSockets"])


@router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket, token: str = Query(None)):
    """
    WebSocket endpoint for admin dashboard subscribers.
    Receives real-time system events (device status, new scans, alerts, camera updates).
    """
    # Verify admin token if provided
    if token:
        payload = verify_access_token(token)
        if not payload:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await ws_manager.connect_dashboard(websocket)
    try:
        while True:
            # Keepalive / ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect_dashboard(websocket)
    except Exception as e:
        logger.debug(f"Dashboard WS error: {e}")
        await ws_manager.disconnect_dashboard(websocket)


@router.websocket("/ws/client/{device_uuid}")
async def websocket_client(websocket: WebSocket, device_uuid: str):
    """
    Persistent signaling channel for the NETSENTRY client app.
    Used for instant camera permission prompts and live heartbeat.
    """
    await ws_manager.connect_client(device_uuid, websocket)
    try:
        while True:
            raw_msg = await websocket.receive_text()
            try:
                msg = json.loads(raw_msg)
                mtype = msg.get("type")

                if mtype == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))

                elif mtype == "PERMISSION_RESPONSE":
                    # Client responded to camera permission prompt
                    session_uuid = msg.get("session_uuid")
                    allowed = msg.get("allowed", False)
                    await camera_manager.handle_permission_response(
                        session_uuid=session_uuid,
                        device_uuid=device_uuid,
                        approved=allowed
                    )

                elif mtype == "CAMERA_STOPPED":
                    # Client stopped camera feed
                    session_uuid = msg.get("session_uuid")
                    reason = msg.get("reason", "USER_STOPPED")
                    await camera_manager.terminate_session(
                        session_uuid=session_uuid,
                        reason=reason,
                        actor=f"Client ({device_uuid[:8]})",
                        actor_type="CLIENT"
                    )

            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        logger.info(f"Client {device_uuid} disconnected from signaling WS.")
        await ws_manager.disconnect_client(device_uuid)
        # Terminate any active sessions on this device
        db = SessionLocal()
        try:
            device = db.query(Device).filter(Device.device_uuid == device_uuid).first()
            if device:
                active_session = db.query(CameraSession).filter(
                    CameraSession.device_id == device.id,
                    CameraSession.permission_status.in_(["REQUESTED", "APPROVED", "ACTIVE"])
                ).first()
                if active_session:
                    await camera_manager.terminate_session(
                        session_uuid=active_session.session_uuid,
                        reason="CLIENT_DISCONNECTED",
                        actor="System",
                        actor_type="SYSTEM"
                    )
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Client WS error for {device_uuid}: {e}")
        await ws_manager.disconnect_client(device_uuid)


@router.websocket("/ws/camera/stream/{session_uuid}")
async def websocket_camera_stream(
    websocket: WebSocket,
    session_uuid: str,
    role: str = Query("viewer", regex="^(viewer|producer)$"),
    token: str = Query(None)
):
    """
    Authenticated video stream relay over WebSocket.
    Role 'producer': The enrolled client pushing JPEG frames.
    Role 'viewer': The admin browser viewing the live feed.
    Strictly verifies that permission was explicitly approved.
    """
    db = SessionLocal()
    try:
        session = db.query(CameraSession).filter(CameraSession.session_uuid == session_uuid).first()
        if not session:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Session not found")
            return

        if session.permission_status not in ["APPROVED", "ACTIVE"]:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Camera permission not granted")
            return
    finally:
        db.close()

    if role == "producer":
        # Client publishing video frames
        await ws_manager.register_stream_producer(session_uuid, websocket)
        try:
            while True:
                # Receive binary JPEG frame from client
                frame_bytes = await websocket.receive_bytes()
                # Relay to admin viewers
                await ws_manager.relay_camera_frame(session_uuid, frame_bytes)
        except WebSocketDisconnect:
            await ws_manager.unregister_stream_producer(session_uuid)
            await camera_manager.terminate_session(
                session_uuid=session_uuid,
                reason="CLIENT_STREAM_DISCONNECTED",
                actor="System",
                actor_type="SYSTEM"
            )
        except Exception as e:
            logger.error(f"Stream producer error: {e}")
            await ws_manager.unregister_stream_producer(session_uuid)
    else:
        # Admin viewer subscribing to stream
        if token:
            payload = verify_access_token(token)
            if not payload:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

        await ws_manager.register_stream_viewer(session_uuid, websocket)
        try:
            while True:
                # Keep alive
                await websocket.receive_text()
        except WebSocketDisconnect:
            await ws_manager.unregister_stream_viewer(session_uuid, websocket)
        except Exception:
            await ws_manager.unregister_stream_viewer(session_uuid, websocket)
