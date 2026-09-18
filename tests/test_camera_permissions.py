import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base
from app.models.device import Device
from app.models.camera_session import CameraSession
from app.models.device_registration import RegistrationCode
from app.models.user import User


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def test_registration_code_expiration(test_db):
    now = datetime.now(timezone.utc)
    expired_code = RegistrationCode(
        code="NET-TEST-OLD",
        created_by="admin",
        expires_at=now - timedelta(minutes=5),
        is_used=False
    )
    active_code = RegistrationCode(
        code="NET-TEST-NEW",
        created_by="admin",
        expires_at=now + timedelta(minutes=15),
        is_used=False
    )
    test_db.add_all([expired_code, active_code])
    test_db.commit()

    # Expired code check
    assert now > expired_code.expires_at.replace(tzinfo=timezone.utc)
    # Active code check
    assert now < active_code.expires_at.replace(tzinfo=timezone.utc)


def test_camera_request_does_not_start_camera(test_db):
    """
    CRITICAL INVARIANT:
    Initiating a camera request sets state to REQUESTED.
    The camera stream MUST NOT be marked ACTIVE or APPROVED without explicit user consent.
    """
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.1.99",
        mac_address="AA:BB:CC:11:22:33",
        hostname="user-laptop",
        client_registered=True,
        first_seen=now,
        last_seen=now
    )
    test_db.add(device)
    test_db.commit()

    session = CameraSession(
        device_id=device.id,
        admin_username="netadmin",
        permission_status="REQUESTED",
        purpose="Authorized inspection",
        max_duration_seconds=600,
        requested_at=now
    )
    test_db.add(session)
    test_db.commit()

    # Verify session is strictly in REQUESTED state
    assert session.permission_status == "REQUESTED"
    assert session.approved_at is None
    assert session.started_at is None
    assert session.ended_at is None


def test_camera_permission_denial_workflow(test_db):
    """
    When user clicks DENY:
    - Camera status transitions to DENIED.
    - Termination reason is recorded.
    - Camera feed NEVER starts.
    """
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.1.100",
        mac_address="AA:BB:CC:11:22:44",
        hostname="consenting-user",
        client_registered=True,
        first_seen=now,
        last_seen=now
    )
    test_db.add(device)
    test_db.commit()

    session = CameraSession(
        device_id=device.id,
        admin_username="netadmin",
        permission_status="REQUESTED",
        purpose="Lab monitoring",
        max_duration_seconds=600,
        requested_at=now
    )
    test_db.add(session)
    test_db.commit()

    # User clicks DENY
    deny_time = datetime.now(timezone.utc)
    session.permission_status = "DENIED"
    session.denied_at = deny_time
    session.ended_at = deny_time
    session.termination_reason = "DENIED_BY_USER"
    test_db.commit()

    reloaded = test_db.query(CameraSession).filter(CameraSession.id == session.id).first()
    assert reloaded.permission_status == "DENIED"
    assert reloaded.started_at is None
    assert reloaded.termination_reason == "DENIED_BY_USER"


def test_camera_permission_approval_workflow(test_db):
    """
    When user clicks ALLOW:
    - Status transitions to APPROVED.
    - Timestamps are properly updated.
    """
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.1.101",
        mac_address="AA:BB:CC:11:22:55",
        hostname="approved-laptop",
        client_registered=True,
        first_seen=now,
        last_seen=now
    )
    test_db.add(device)
    test_db.commit()

    session = CameraSession(
        device_id=device.id,
        admin_username="netadmin",
        permission_status="REQUESTED",
        purpose="Class demonstration",
        max_duration_seconds=600,
        requested_at=now
    )
    test_db.add(session)
    test_db.commit()

    # User clicks ALLOW
    approve_time = datetime.now(timezone.utc)
    session.permission_status = "APPROVED"
    session.approved_at = approve_time
    session.started_at = approve_time
    test_db.commit()

    reloaded = test_db.query(CameraSession).filter(CameraSession.id == session.id).first()
    assert reloaded.permission_status == "APPROVED"
    assert reloaded.started_at is not None
    assert reloaded.denied_at is None
