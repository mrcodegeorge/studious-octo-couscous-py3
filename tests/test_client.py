import pytest
from client.network import get_local_device_info
from client.camera import CameraStreamer


def test_client_local_info_detection():
    ip, mac, hostname = get_local_device_info()
    assert ip is not None
    assert len(mac.split(":")) == 6
    assert hostname is not None


def test_camera_streamer_synthetic_frame():
    streamer = CameraStreamer(ws_url="ws://127.0.0.1:8000", session_uuid="test-uuid-1234")
    frame = streamer._generate_synthetic_frame(1)
    assert isinstance(frame, bytes)
    assert len(frame) > 1000  # Valid JPEG binary bytes
    # Check JPEG header SOI marker 0xFF 0xD8
    assert frame[:2] == b'\xff\xd8'
