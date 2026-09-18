import pytest
import os
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.database import Base, get_db
from app.main import app
from app.services.web_filter_service import WebFilterService
from app.models.web_policy import WebFilterRule, WebActivityLog, VpnRestrictionPolicy
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from client.blocker import HostsBlocker, START_TAG, END_TAG
from client.activity_monitor import ActivityMonitor


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_rule_crud(db_session):
    rule = WebFilterService.create_rule(
        db=db_session,
        domain_pattern="*.distraction.com",
        category="Entertainment",
        action="BLOCK",
        description="Block streaming games",
        is_active=True,
    )
    assert rule.id is not None
    assert rule.domain_pattern == "*.distraction.com"

    # Fetch
    rules = WebFilterService.get_rules(db_session)
    assert len(rules) == 1

    # Update
    updated = WebFilterService.update_rule(
        db=db_session, rule_id=rule.id, category="Productivity", is_active=False
    )
    assert updated.category == "Productivity"
    assert updated.is_active is False

    # Delete
    deleted = WebFilterService.delete_rule(db_session, rule.id)
    assert deleted is True
    assert len(WebFilterService.get_rules(db_session)) == 0


def test_domain_pattern_matching(db_session):
    rules = [
        WebFilterRule(domain_pattern="*.tiktok.com", is_active=True, action="BLOCK"),
        WebFilterRule(domain_pattern="facebook.com", is_active=True, action="BLOCK"),
        WebFilterRule(domain_pattern="*gambling*", is_active=True, action="BLOCK"),
        WebFilterRule(domain_pattern="allowed.com", is_active=False, action="BLOCK"),
    ]

    # Subdomain wildcards
    matched, r = WebFilterService.match_domain("v16.tiktok.com", rules)
    assert matched is True
    assert r.domain_pattern == "*.tiktok.com"

    matched, r = WebFilterService.match_domain("tiktok.com", rules)
    assert matched is True

    # Exact and www subdomain
    matched, r = WebFilterService.match_domain("facebook.com", rules)
    assert matched is True
    matched, r = WebFilterService.match_domain("www.facebook.com", rules)
    assert matched is True

    # Keyword wildcard
    matched, r = WebFilterService.match_domain("onlinegamblingsite.com", rules)
    assert matched is True

    # Inactive rule shouldn't match
    matched, r = WebFilterService.match_domain("allowed.com", rules)
    assert matched is False

    # Unrestricted domain
    matched, r = WebFilterService.match_domain("wikipedia.org", rules)
    assert matched is False


def test_activity_logging_and_alerts(db_session):
    # Create block rule
    WebFilterService.create_rule(
        db=db_session,
        domain_pattern="*.restricted.org",
        category="Restricted",
        action="BLOCK",
        description="Block restricted site",
        is_active=True,
    )

    # 1. Allowed domain access
    allowed_entry = WebFilterService.record_activity_entry(
        db=db_session,
        domain="google.com",
        ip_address="192.168.1.55",
        process_name="chrome.exe",
    )
    assert allowed_entry.action_taken == "ALLOWED"
    assert db_session.query(Alert).count() == 0

    # 2. Blocked domain access
    blocked_entry = WebFilterService.record_activity_entry(
        db=db_session,
        domain="sub.restricted.org",
        ip_address="192.168.1.55",
        process_name="msedge.exe",
        is_vpn=True,
    )
    assert blocked_entry.action_taken == "BLOCK"
    assert blocked_entry.is_vpn_traffic is True

    # Verify Alert was created
    alerts = db_session.query(Alert).all()
    assert len(alerts) == 1
    assert "restricted.org" in alerts[0].message

    # Verify AuditLog was created
    audits = db_session.query(AuditLog).all()
    assert len(audits) == 1
    assert audits[0].event == "WEB_FILTER_BLOCK"


def test_vpn_policy_management(db_session):
    policy = WebFilterService.get_vpn_policy(db_session)
    assert policy.block_all_vpns is True

    # Update
    updated = WebFilterService.update_vpn_policy(
        db=db_session,
        block_all_vpns=False,
        custom_blocked_adapters="test_adapter,wireguard",
    )
    assert updated.block_all_vpns is False
    assert "test_adapter" in updated.custom_blocked_adapters


def test_hosts_blocker_surgical_injection():
    # Use temporary file to simulate OS hosts file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as tf:
        tf.write("127.0.0.1 localhost\n::1 localhost\n# Existing user entries\n192.168.1.1 router.local\n")
        temp_path = tf.name

    try:
        blocker = HostsBlocker(hosts_path=temp_path)
        assert blocker.is_writable() is True

        # Sync rules
        success = blocker.sync_blocked_domains(["*.tiktok.com", "bet365.com"])
        assert success is True

        with open(temp_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert START_TAG in content
        assert END_TAG in content
        assert "0.0.0.0 tiktok.com" in content
        assert "0.0.0.0 www.tiktok.com" in content
        assert "0.0.0.0 bet365.com" in content
        # Ensure original entries preserved
        assert "192.168.1.1 router.local" in content

        # Clean removal
        blocker.clear_all_blocks()
        with open(temp_path, "r", encoding="utf-8") as f:
            clean_content = f.read()

        assert START_TAG not in clean_content
        assert "0.0.0.0 tiktok.com" not in clean_content
        assert "192.168.1.1 router.local" in clean_content

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_client_policy_and_activity_api(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        # 1. Fetch public client policy
        resp = client.get("/api/v1/web-filter/client-policy")
        assert resp.status_code == 200
        data = resp.json()
        assert "blocked_domains" in data
        assert "vpn_policy" in data

        # 2. Report activity batch
        report_payload = {
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "ip_address": "192.168.1.99",
            "activities": [
                {"domain": "github.com", "process_name": "chrome.exe", "is_vpn": False},
                {"domain": "tiktok.com", "process_name": "chrome.exe", "is_vpn": True},
            ]
        }
        batch_resp = client.post("/api/v1/web-filter/activity", json=report_payload)
        assert batch_resp.status_code == 200
        batch_data = batch_resp.json()
        assert batch_data["recorded_count"] == 2
    finally:
        app.dependency_overrides.clear()
