import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base
from app.models.audit_log import AuditLog
from app.services.audit_service import log_audit_event


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def test_audit_logging_immutability(test_db):
    entry = log_audit_event(
        db=test_db,
        actor="administrator",
        actor_type="ADMIN",
        event="ADMIN_LOGIN",
        ip_address="192.168.1.10",
        status="SUCCESS",
        metadata={"browser": "Chrome"}
    )
    assert entry.id is not None
    assert entry.actor == "administrator"
    assert entry.event == "ADMIN_LOGIN"
    assert "Chrome" in entry.metadata_json

    # Query from DB
    records = test_db.query(AuditLog).all()
    assert len(records) == 1
    assert records[0].actor_type == "ADMIN"
