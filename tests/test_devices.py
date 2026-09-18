import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base
from app.models.device import Device
from app.services.audit_service import log_audit_event


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def test_device_creation_and_trust(test_db):
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.1.50",
        mac_address="AA:BB:CC:DD:EE:01",
        hostname="lab-workstation",
        vendor="Dell Inc.",
        status="ONLINE",
        trusted=False,
        client_registered=False,
        first_seen=now,
        last_seen=now
    )
    test_db.add(device)
    test_db.commit()

    assert device.id is not None
    assert device.trusted is False

    # Mark as trusted
    device.trusted = True
    device.trusted_by = "admin"
    device.trusted_at = datetime.now(timezone.utc)
    test_db.commit()

    saved = test_db.query(Device).filter(Device.id == device.id).first()
    assert saved.trusted is True
    assert saved.trusted_by == "admin"


def test_device_timeline_generation(test_db):
    now = datetime.now(timezone.utc)
    device = Device(
        ip_address="192.168.1.55",
        mac_address="AA:BB:CC:DD:EE:02",
        hostname="test-device",
        status="ONLINE",
        first_seen=now,
        last_seen=now
    )
    test_db.add(device)
    test_db.commit()

    log_audit_event(test_db, actor="Scanner", actor_type="SYSTEM", event="DEVICE_DISCOVERED", device_id=device.id)
    log_audit_event(test_db, actor="admin", actor_type="ADMIN", event="DEVICE_TRUST_GRANTED", device_id=device.id)

    from app.models.audit_log import AuditLog
    logs = test_db.query(AuditLog).filter(AuditLog.device_id == device.id).all()
    assert len(logs) == 2
    assert [l.event for l in logs] == ["DEVICE_DISCOVERED", "DEVICE_TRUST_GRANTED"]
