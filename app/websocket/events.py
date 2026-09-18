from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel


class EventType(str, Enum):
    DEVICE_DISCOVERED = "DEVICE_DISCOVERED"
    DEVICE_ONLINE = "DEVICE_ONLINE"
    DEVICE_OFFLINE = "DEVICE_OFFLINE"
    DEVICE_UPDATED = "DEVICE_UPDATED"
    CLIENT_CONNECTED = "CLIENT_CONNECTED"
    CLIENT_DISCONNECTED = "CLIENT_DISCONNECTED"
    CAMERA_REQUESTED = "CAMERA_REQUESTED"
    CAMERA_APPROVED = "CAMERA_APPROVED"
    CAMERA_DENIED = "CAMERA_DENIED"
    CAMERA_STARTED = "CAMERA_STARTED"
    CAMERA_STOPPED = "CAMERA_STOPPED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    ALERT_NEW = "ALERT_NEW"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    WEB_POLICY_UPDATED = "WEB_POLICY_UPDATED"
    WEB_FILTER_VIOLATION = "WEB_FILTER_VIOLATION"



class SystemEvent(BaseModel):
    event_type: EventType
    timestamp: str
    data: Dict[str, Any]
    message: Optional[str] = None

    @classmethod
    def create(cls, event_type: EventType, data: Dict[str, Any], message: Optional[str] = None):
        return cls(
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
            message=message or event_type.value,
        )
