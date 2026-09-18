import socket
import uuid
import re
import subprocess
import sys
import httpx
from typing import Tuple, Optional


def get_local_device_info() -> Tuple[str, str, str]:
    """
    Detects local machine IP address, MAC address, and Hostname.
    Returns (ip, mac, hostname).
    """
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    # Fetch MAC address
    mac_raw = f"{uuid.getnode():012X}"
    mac = ":".join(mac_raw[i:i+2] for i in range(0, 12, 2))

    return local_ip, mac, hostname


class ClientNetworkManager:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")
        self.client = httpx.Client(timeout=10.0)

    def register(self, registration_code: str, ip: str, mac: str, hostname: str) -> dict:
        """Register device with NETSENTRY server using admin registration code."""
        url = f"{self.server_url}/api/client/register"
        payload = {
            "registration_code": registration_code.strip().upper(),
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "client_version": "1.0.0"
        }
        resp = self.client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()

    def send_heartbeat(self, device_uuid: str, client_token: str) -> bool:
        """Send periodic heartbeat to maintain online status."""
        url = f"{self.server_url}/api/client/heartbeat"
        headers = {
            "X-Device-UUID": device_uuid,
            "X-Client-Token": client_token
        }
        try:
            resp = self.client.post(url, json={"client_version": "1.0.0"}, headers=headers)
            return resp.status_code == 200
        except Exception:
            return False

    def send_permission_response(self, device_uuid: str, client_token: str, session_uuid: str, allowed: bool) -> bool:
        """Send user's ALLOW or DENY choice to server."""
        url = f"{self.server_url}/api/client/camera/permission"
        headers = {
            "X-Device-UUID": device_uuid,
            "X-Client-Token": client_token
        }
        payload = {
            "session_uuid": session_uuid,
            "allowed": allowed
        }
        try:
            resp = self.client.post(url, json=payload, headers=headers)
            return resp.status_code == 200
        except Exception:
            return False

    def stop_camera_session(self, device_uuid: str, client_token: str, session_uuid: str) -> bool:
        """Inform server that user clicked [STOP CAMERA]."""
        url = f"{self.server_url}/api/client/camera/stop"
        headers = {
            "X-Device-UUID": device_uuid,
            "X-Client-Token": client_token
        }
        try:
            resp = self.client.post(url, json={"session_uuid": session_uuid}, headers=headers)
            return resp.status_code == 200
        except Exception:
            return False
