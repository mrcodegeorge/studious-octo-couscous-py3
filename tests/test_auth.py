import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base
from app.models.user import User
from app.services.authentication import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    authenticate_admin,
)
from fastapi import HTTPException


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def test_password_hashing():
    raw = "SecureP@ssw0rd2026!"
    hashed = hash_password(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_token_generation():
    data = {"sub": "admin_test", "role": "admin", "id": 1}
    token = create_access_token(data)
    assert isinstance(token, str)
    payload = verify_access_token(token)
    assert payload is not None
    assert payload["sub"] == "admin_test"
    assert payload["role"] == "admin"


def test_authenticate_admin_success(test_db):
    user = User(
        username="netadmin",
        hashed_password=hash_password("SuperSecret123"),
        role="admin",
        is_active=True
    )
    test_db.add(user)
    test_db.commit()

    auth_user = authenticate_admin(test_db, "netadmin", "SuperSecret123")
    assert auth_user.id == user.id
    assert auth_user.failed_logins == 0


def test_account_lockout_after_max_failed_attempts(test_db):
    user = User(
        username="target_admin",
        hashed_password=hash_password("CorrectPassword!"),
        role="admin",
        is_active=True
    )
    test_db.add(user)
    test_db.commit()

    # Attempt wrong password 5 times
    for i in range(4):
        with pytest.raises(HTTPException) as exc:
            authenticate_admin(test_db, "target_admin", "WrongGuess")
        assert exc.value.status_code == 401

    # 5th failed attempt should trigger lockout
    with pytest.raises(HTTPException) as exc:
        authenticate_admin(test_db, "target_admin", "WrongGuess")
    assert exc.value.status_code == 403
    assert "locked" in exc.value.detail.lower()

    # Even with the correct password, login should now be blocked
    with pytest.raises(HTTPException) as exc:
        authenticate_admin(test_db, "target_admin", "CorrectPassword!")
    assert exc.value.status_code == 403
