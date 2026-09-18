import logging
import json
import asyncio
from typing import Dict, Set, Optional, Any
from fastapi import WebSocket
from app.websocket.events import SystemEvent, EventType

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self):
        # Admin dashboard connections
        self.dashboard_connections: Set[WebSocket] = set()

        # Client device connections: {device_uuid: WebSocket}
        self.client_connections: Dict[str, WebSocket] = {}

        # Camera streaming viewers: {session_uuid: Set[WebSocket]}
        self.stream_viewers: Dict[str, Set[WebSocket]] = {}

        # Camera streaming producers (clients): {session_uuid: WebSocket}
        self.stream_producers: Dict[str, WebSocket] = {}

        self._lock = asyncio.Lock()

    # --- Dashboard Subscriptions ---
    async def connect_dashboard(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.dashboard_connections.add(websocket)
        logger.info(f"Dashboard client connected. Active connections: {len(self.dashboard_connections)}")

    async def disconnect_dashboard(self, websocket: WebSocket):
        async with self._lock:
            self.dashboard_connections.discard(websocket)
        logger.info(f"Dashboard client disconnected. Remaining: {len(self.dashboard_connections)}")

    async def broadcast_event(self, event: SystemEvent):
        """Broadcast a system event to all connected admin dashboards."""
        payload = event.model_dump_json()
        disconnected = set()
        for ws in list(self.dashboard_connections):
            try:
                await ws.send_text(payload)
            except Exception as e:
                logger.debug(f"Failed to send to dashboard: {e}")
                disconnected.add(ws)

        if disconnected:
            async with self._lock:
                self.dashboard_connections.difference_update(disconnected)

    # --- Client Connections ---
    async def connect_client(self, device_uuid: str, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.client_connections[device_uuid] = websocket
        logger.info(f"NETSENTRY client '{device_uuid}' connected.")

    async def disconnect_client(self, device_uuid: str):
        async with self._lock:
            self.client_connections.pop(device_uuid, None)
        logger.info(f"NETSENTRY client '{device_uuid}' disconnected.")

    def is_client_connected(self, device_uuid: str) -> bool:
        return device_uuid in self.client_connections

    async def send_to_client(self, device_uuid: str, message: Dict[str, Any]) -> bool:
        """Send a message to a specific connected client."""
        ws = self.client_connections.get(device_uuid)
        if ws:
            try:
                await ws.send_text(json.dumps(message))
                return True
            except Exception as e:
                logger.error(f"Error sending message to client {device_uuid}: {e}")
                await self.disconnect_client(device_uuid)
        return False

    # --- Live Camera Stream Relay ---
    async def register_stream_producer(self, session_uuid: str, websocket: WebSocket):
        """Client connects as camera stream producer."""
        await websocket.accept()
        async with self._lock:
            self.stream_producers[session_uuid] = websocket
        logger.info(f"Camera stream producer connected for session {session_uuid}")

    async def unregister_stream_producer(self, session_uuid: str):
        async with self._lock:
            self.stream_producers.pop(session_uuid, None)
        logger.info(f"Camera stream producer disconnected for session {session_uuid}")

    async def register_stream_viewer(self, session_uuid: str, websocket: WebSocket):
        """Admin connects to view live camera stream."""
        await websocket.accept()
        async with self._lock:
            if session_uuid not in self.stream_viewers:
                self.stream_viewers[session_uuid] = set()
            self.stream_viewers[session_uuid].add(websocket)
        logger.info(f"Viewer connected to camera session {session_uuid}")

    async def unregister_stream_viewer(self, session_uuid: str, websocket: WebSocket):
        async with self._lock:
            if session_uuid in self.stream_viewers:
                self.stream_viewers[session_uuid].discard(websocket)
                if not self.stream_viewers[session_uuid]:
                    del self.stream_viewers[session_uuid]

    async def relay_camera_frame(self, session_uuid: str, frame_data: bytes):
        """Relay raw JPEG frame from client producer to all active admin viewers."""
        viewers = self.stream_viewers.get(session_uuid, set())
        dead_viewers = set()
        for viewer in list(viewers):
            try:
                await viewer.send_bytes(frame_data)
            except Exception:
                dead_viewers.add(viewer)

        if dead_viewers:
            async with self._lock:
                if session_uuid in self.stream_viewers:
                    self.stream_viewers[session_uuid].difference_update(dead_viewers)


ws_manager = ConnectionManager()
