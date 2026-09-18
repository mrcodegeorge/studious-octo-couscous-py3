import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.database.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.device import Device
from app.models.camera_session import CameraSession
from app.models.audit_log import AuditLog
from app.models.device_registration import RegistrationCode
from app.services.authentication import hash_password


@pytest.fixture(scope="module")
def client():
    # Initialize database and set fast demo mode for test execution
    from app.config import settings
    settings.DEMO_MODE = True
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Ensure admin user
    db.query(User).filter(User.username == "e2e_admin").delete()
    admin = User(
        username="e2e_admin",
        hashed_password=hash_password("E2E_Test_Password123!"),
        role="admin",
        is_active=True
    )
    db.add(admin)
    db.commit()
    db.close()

    with TestClient(app) as tc:
        yield tc


def test_complete_consent_workflow_allow_and_deny(client):
    # 1. Admin Login
    login_res = client.post("/api/auth/login", json={
        "username": "e2e_admin",
        "password": "E2E_Test_Password123!"
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Network Status & Discovery
    net_res = client.get("/api/network/status", headers=headers)
    assert net_res.status_code == 200
    assert "authorized_subnet" in net_res.json()

    # 3. Admin generates ephemeral registration code
    code_res = client.post("/api/client/generate-code", headers=headers)
    assert code_res.status_code == 200
    reg_code = code_res.json()["code"]
    assert reg_code.startswith("NET-")

    # 4. Consenting client registers using code
    reg_client_res = client.post("/api/client/register", json={
        "registration_code": reg_code,
        "ip_address": "192.168.1.188",
        "mac_address": "AA:BB:CC:99:88:77",
        "hostname": "George-Consenting-Laptop",
        "client_version": "1.0.0"
    })
    assert reg_client_res.status_code == 200
    device_uuid = reg_client_res.json()["device_uuid"]
    device_id = reg_client_res.json()["device_id"]
    client_token = reg_client_res.json()["client_token"]
    client_headers = {
        "X-Device-UUID": device_uuid,
        "X-Client-Token": client_token
    }

    # 5. Client sends periodic heartbeat
    hb_res = client.post("/api/client/heartbeat", json={"client_version": "1.0.0"}, headers=client_headers)
    assert hb_res.status_code == 200

    # 6. Verify device is present and trusted in inventory
    dev_res = client.get(f"/api/devices/{device_id}", headers=headers)
    assert dev_res.status_code == 200
    assert dev_res.json()["device"]["client_registered"] is True

    # 7. WORKFLOW A: DENIAL TEST
    # Admin requests camera access
    from app.websocket.manager import ws_manager
    class MockWS:
        async def send_text(self, msg):
            pass

    # Simulate client connected in WebSocket manager
    ws_manager.client_connections[device_uuid] = MockWS()

    cam_req_res = client.post(f"/api/camera/request/{device_id}", json={
        "purpose": "Security compliance inspection",
        "duration_minutes": 10
    }, headers=headers)
    assert cam_req_res.status_code == 200
    session_uuid_1 = cam_req_res.json()["session_uuid"]
    assert cam_req_res.json()["permission_status"] == "REQUESTED"

    # Client user receives prompt and clicks DENY
    deny_res = client.post("/api/client/camera/permission", json={
        "session_uuid": session_uuid_1,
        "allowed": False
    }, headers=client_headers)
    assert deny_res.status_code == 200

    # Verify session is DENIED
    session_chk = client.get(f"/api/camera/sessions/{session_uuid_1}", headers=headers)
    assert session_chk.json()["permission_status"] == "DENIED"
    assert session_chk.json()["termination_reason"] == "DENIED_BY_USER"

    # 8. WORKFLOW B: APPROVAL AND USER TERMINATION TEST
    ws_manager.client_connections[device_uuid] = MockWS()
    cam_req_res2 = client.post(f"/api/camera/request/{device_id}", json={
        "purpose": "Laboratory demonstration",
        "duration_minutes": 10
    }, headers=headers)
    assert cam_req_res2.status_code == 200
    session_uuid_2 = cam_req_res2.json()["session_uuid"]

    # Client user receives prompt and clicks ALLOW
    allow_res = client.post("/api/client/camera/permission", json={
        "session_uuid": session_uuid_2,
        "allowed": True
    }, headers=client_headers)
    assert allow_res.status_code == 200

    # Verify session is APPROVED and started
    session_chk2 = client.get(f"/api/camera/sessions/{session_uuid_2}", headers=headers)
    assert session_chk2.json()["permission_status"] == "APPROVED"
    assert session_chk2.json()["approved_at"] is not None

    # Client user clicks [STOP CAMERA]
    stop_res = client.post("/api/client/camera/stop", json={
        "session_uuid": session_uuid_2
    }, headers=client_headers)
    assert stop_res.status_code == 200

    # Verify session ended with USER_STOPPED
    session_chk3 = client.get(f"/api/camera/sessions/{session_uuid_2}", headers=headers)
    assert session_chk3.json()["permission_status"] == "TERMINATED"
    assert session_chk3.json()["termination_reason"] == "USER_STOPPED"

    # 9. Verify Audit Trail Contains Complete Handshake
    audit_res = client.get("/api/audit", headers=headers)
    assert audit_res.status_code == 200
    events = [l["event"] for l in audit_res.json()]
    assert "ADMIN_LOGIN" in events
    assert "REGISTRATION_CODE_GENERATED" in events
    assert "CLIENT_REGISTERED" in events
    assert "CAMERA_REQUESTED" in events
    assert "CAMERA_DENIED" in events
    assert "CAMERA_APPROVED" in events
    assert "CAMERA_STARTED" in events
    assert "CAMERA_STOPPED" in events

    # Clean up mock ws
    ws_manager.client_connections.pop(device_uuid, None)
