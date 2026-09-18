import time
import io
import logging
import threading
import asyncio
from typing import Optional, Callable
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

# Check OpenCV availability
try:
    import cv2
    HAVE_CV2 = True
except ImportError:
    HAVE_CV2 = False


class CameraStreamer:
    def __init__(self, ws_url: str, session_uuid: str, on_frame: Optional[Callable] = None):
        self.ws_url = ws_url
        self.session_uuid = session_uuid
        self.on_frame = on_frame  # Callback for local GUI preview
        self.is_streaming = False
        self._thread: Optional[threading.Thread] = None
        self._cap = None
        self.has_physical_cam = False

    def start(self):
        """Start camera capture and streaming thread."""
        if self.is_streaming:
            return
        self.is_streaming = True
        self._thread = threading.Thread(target=self._run_stream, daemon=True)
        self._thread.start()

    def stop(self):
        """Immediately terminate camera hardware and streaming."""
        self.is_streaming = False
        if self._cap:
            try:
                self._cap.release()
            except Exception:
                pass
            self._cap = None

    def _open_camera(self):
        """Attempt to open physical hardware camera with OpenCV."""
        if not HAVE_CV2:
            return False
        try:
            # Try index 0
            cap = cv2.VideoCapture(0)
            if cap.isOpened():
                ret, _ = cap.read()
                if ret:
                    self._cap = cap
                    self.has_physical_cam = True
                    return True
            cap.release()
        except Exception as e:
            logger.warning(f"Could not open physical webcam: {e}")
        return False

    def _generate_synthetic_frame(self, frame_num: int) -> bytes:
        """
        If physical camera is occupied or absent in VM/test environment,
        generate an explicit test frame clearly stating status.
        """
        img = Image.new("RGB", (640, 480), color=(15, 23, 42))  # Dark slate
        draw = ImageDraw.Draw(img)

        # Title
        draw.rectangle([(20, 20), (620, 70)], fill=(30, 41, 59), outline=(0, 242, 254), width=2)
        draw.text((40, 35), "NETSENTRY AUTHORIZED CAMERA SESSION", fill=(0, 242, 254))

        # Status
        status_text = "LIVE HARDWARE WEBCAM ACTIVE" if self.has_physical_cam else "HARDWARE CAMERA UNAVAILABLE / TEST FEED"
        draw.text((40, 100), f"Status: {status_text}", fill=(255, 255, 255))
        draw.text((40, 130), f"Session UUID: {self.session_uuid}", fill=(148, 163, 184))
        draw.text((40, 160), f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}", fill=(148, 163, 184))

        # Visual indicator
        dot_color = (16, 185, 129) if (frame_num % 10 < 5) else (239, 68, 68)
        draw.ellipse([(40, 200), (60, 220)], fill=dot_color)
        draw.text((70, 203), "ACTIVE CONSENT-BASED STREAM", fill=(255, 255, 255))

        # Frame counter
        draw.text((40, 240), f"Frame #{frame_num}", fill=(100, 116, 139))
        draw.rectangle([(20, 420), (620, 460)], fill=(30, 41, 59))
        draw.text((40, 430), "Consent verified - User can terminate anytime via [STOP CAMERA]", fill=(203, 213, 225))

        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=80)
        return buf.getvalue()

    def _run_stream(self):
        """Asynchronous streaming loop connecting over WebSocket."""
        asyncio.run(self._async_stream_loop())

    async def _async_stream_loop(self):
        import websockets
        # Construct WebSocket streaming URL
        ws_endpoint = f"{self.ws_url}/ws/camera/stream/{self.session_uuid}?role=producer"
        # Convert http(s) to ws(s)
        if ws_endpoint.startswith("http://"):
            ws_endpoint = "ws://" + ws_endpoint[7:]
        elif ws_endpoint.startswith("https://"):
            ws_endpoint = "wss://" + ws_endpoint[8:]

        self._open_camera()
        frame_idx = 0

        while self.is_streaming:
            try:
                async with websockets.connect(ws_endpoint) as ws:
                    logger.info(f"Client camera connected to streaming relay {ws_endpoint}")
                    while self.is_streaming:
                        frame_bytes = None

                        if self._cap and self.has_physical_cam:
                            ret, frame = self._cap.read()
                            if ret:
                                # Overlay watermark
                                cv2.putText(
                                    frame,
                                    f"NETSENTRY LIVE - {time.strftime('%H:%M:%S')}",
                                    (15, 30),
                                    cv2.FONT_HERSHEY_SIMPLEX,
                                    0.7,
                                    (0, 255, 255),
                                    2
                                )
                                _, enc = cv2.imencode('.jpg', frame, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
                                frame_bytes = enc.tobytes()

                        if not frame_bytes:
                            frame_bytes = self._generate_synthetic_frame(frame_idx)

                        frame_idx += 1

                        # Send binary frame to server
                        await ws.send(frame_bytes)

                        # Provide local preview if callback supplied
                        if self.on_frame:
                            self.on_frame(frame_bytes)

                        # Target ~15 FPS
                        await asyncio.sleep(0.066)

            except Exception as e:
                if not self.is_streaming:
                    break
                logger.warning(f"Streaming error: {e}. Reconnecting in 2s...")
                await asyncio.sleep(2.0)
