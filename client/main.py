import sys
from pathlib import Path

# Ensure project root and client directory are in sys.path regardless of execution context
CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
CLIENT_DIR = CURRENT_FILE.parent

for path_str in [str(PROJECT_ROOT), str(CLIENT_DIR)]:
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

import argparse
import time
import json
import threading
import logging
import asyncio
from typing import Optional
import websockets

try:
    from client.config import load_client_config, save_client_config
    from client.network import get_local_device_info, ClientNetworkManager
    from client.camera import CameraStreamer
    from client.ui import NetsentryClientUI
except ImportError:
    from config import load_client_config, save_client_config
    from network import get_local_device_info, ClientNetworkManager
    from camera import CameraStreamer
    from ui import NetsentryClientUI

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("netsentry-client")


class NetsentryClientApp:
    def __init__(self, cli_mode: bool = False):
        self.cli_mode = cli_mode
        self.config = load_client_config()
        self.local_ip, self.mac_address, self.hostname = get_local_device_info()

        self.net_manager = ClientNetworkManager(self.config.get("server_url", "http://127.0.0.1:8000"))
        self.streamer: Optional[CameraStreamer] = None

        self.ws_thread: Optional[threading.Thread] = None
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.is_running = True

        self.ui: Optional[NetsentryClientUI] = None
        if not self.cli_mode:
            self.ui = NetsentryClientUI(
                local_ip=self.local_ip,
                mac_address=self.mac_address,
                hostname=self.hostname,
                on_register=self.handle_register,
                on_permission_response=self.handle_permission_response,
                on_stop_camera=self.handle_stop_camera,
                on_privacy_click=self.handle_privacy_click
            )
            # Update initial UI state if already registered
            if self.config.get("is_registered"):
                self.ui.set_connection_status(True, self.config.get("device_uuid", "")[:8])

    def start(self):
        """Start client services and UI mainloop."""
        logger.info(f"NETSENTRY Client started for device: {self.hostname} ({self.local_ip}, MAC: {self.mac_address})")

        # If already registered, start background connection immediately
        if self.config.get("is_registered") and self.config.get("device_uuid"):
            self._start_background_services()

        if self.ui:
            self.ui.run()
        else:
            self._run_cli_loop()

    def handle_register(self, server_url: str, registration_code: str):
        """Called when user submits server URL and registration code."""
        self.net_manager.server_url = server_url.rstrip("/")
        try:
            logger.info(f"Enrolling with server {server_url} using code {registration_code}...")
            res = self.net_manager.register(
                registration_code=registration_code,
                ip=self.local_ip,
                mac=self.mac_address,
                hostname=self.hostname
            )
            self.config["server_url"] = server_url
            self.config["device_uuid"] = res["device_uuid"]
            self.config["client_token"] = res["client_token"]
            self.config["is_registered"] = True
            save_client_config(self.config)

            if self.ui:
                self.ui.set_connection_status(True, res["device_uuid"][:8])

            logger.info(f"Successfully registered as device UUID: {res['device_uuid']}")
            self._start_background_services()
        except Exception as e:
            logger.error(f"Registration failed: {e}")
            if self.ui:
                from tkinter import messagebox
                messagebox.showerror("Registration Failed", f"Could not enroll with server:\n{e}")

    def _start_background_services(self):
        """Start heartbeat loop and WebSocket signaling listener."""
        if not self.heartbeat_thread or not self.heartbeat_thread.is_alive():
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()

        if not self.ws_thread or not self.ws_thread.is_alive():
            self.ws_thread = threading.Thread(target=self._ws_signaling_loop, daemon=True)
            self.ws_thread.start()

    def _heartbeat_loop(self):
        """Periodically ping the server to report online status."""
        while self.is_running:
            token = self.config.get("client_token")
            uuid_str = self.config.get("device_uuid")
            if token and uuid_str:
                self.net_manager.send_heartbeat(uuid_str, token)
            time.sleep(15)

    def _ws_signaling_loop(self):
        """Asynchronous signaling loop for camera permission requests."""
        asyncio.run(self._async_signaling())

    async def _async_signaling(self):
        server_url = self.config.get("server_url", "http://127.0.0.1:8000")
        device_uuid = self.config.get("device_uuid")
        if not device_uuid:
            return

        ws_url = server_url
        if ws_url.startswith("http://"):
            ws_url = "ws://" + ws_url[7:]
        elif ws_url.startswith("https://"):
            ws_url = "wss://" + ws_url[8:]
        endpoint = f"{ws_url}/ws/client/{device_uuid}"

        while self.is_running:
            try:
                async with websockets.connect(endpoint) as ws:
                    logger.info(f"Connected to NETSENTRY signaling hub at {endpoint}")
                    while self.is_running:
                        msg_str = await ws.recv()
                        try:
                            msg = json.loads(msg_str)
                            mtype = msg.get("type")

                            if mtype == "CAMERA_PERMISSION_PROMPT":
                                # Incoming camera access request from administrator
                                session_uuid = msg.get("session_uuid")
                                admin_name = msg.get("admin_username", "Administrator")
                                purpose = msg.get("purpose", "Authorized network monitoring")
                                duration = msg.get("duration_minutes", 10)

                                logger.info(f"Camera permission requested by {admin_name} for session {session_uuid}")
                                if self.ui:
                                    self.ui.root.after(0, self.ui.show_permission_prompt, session_uuid, admin_name, purpose, duration)
                                else:
                                    # CLI mode prompt
                                    print(f"\n[!] CAMERA ACCESS REQUESTED by {admin_name}")
                                    print(f"    Purpose: {purpose} | Duration: {duration} mins")
                                    print("    Type 'allow' or 'deny': ", end="", flush=True)

                            elif mtype == "CAMERA_STOP_COMMAND":
                                # Server or Admin initiated termination
                                session_uuid = msg.get("session_uuid")
                                reason = msg.get("reason", "ADMIN_STOPPED")
                                logger.info(f"Received stop command for session {session_uuid} ({reason})")
                                if self.streamer:
                                    self.streamer.stop()
                                    self.streamer = None
                                if self.ui:
                                    self.ui.root.after(0, self.ui.set_camera_inactive, reason)

                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                if not self.is_running:
                    break
                logger.warning(f"Signaling connection lost: {e}. Reconnecting in 3s...")
                await asyncio.sleep(3.0)

    def handle_permission_response(self, session_uuid: str, allowed: bool):
        """User submitted decision on the visible prompt."""
        device_uuid = self.config.get("device_uuid")
        token = self.config.get("client_token")
        if not device_uuid or not token:
            return

        # Send decision to server
        self.net_manager.send_permission_response(device_uuid, token, session_uuid, allowed)

        if allowed:
            logger.info(f"User APPROVED camera session {session_uuid}. Initiating stream...")
            # Start camera streamer
            self.streamer = CameraStreamer(
                ws_url=self.config.get("server_url", "http://127.0.0.1:8000"),
                session_uuid=session_uuid
            )
            self.streamer.start()

            if self.ui:
                self.ui.set_camera_active(session_uuid, "Network Administrator", 600)
        else:
            logger.info(f"User DENIED camera session {session_uuid}. Camera remains strictly OFF.")
            if self.ui:
                self.ui.set_camera_inactive("Denied by User")

    def handle_stop_camera(self, session_uuid: str):
        """User clicked [STOP CAMERA] in client UI."""
        logger.info(f"User clicked STOP CAMERA for session {session_uuid}")
        if self.streamer:
            self.streamer.stop()
            self.streamer = None

        device_uuid = self.config.get("device_uuid")
        token = self.config.get("client_token")
        if device_uuid and token:
            self.net_manager.stop_camera_session(device_uuid, token, session_uuid)

    def handle_privacy_click(self):
        if self.ui:
            self.ui.show_privacy_dialog()

    def _run_cli_loop(self):
        """Simple interactive loop for headless / CLI demonstration."""
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping client...")
            self.is_running = False


def main():
    parser = argparse.ArgumentParser(description="NETSENTRY Client Node")
    parser.add_argument("--cli", action="store_true", help="Run in CLI headless mode (no Tkinter GUI)")
    args = parser.parse_args()

    app = NetsentryClientApp(cli_mode=args.cli)
    app.start()


if __name__ == "__main__":
    main()
