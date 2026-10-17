from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import User


def _make_token(sub: str, key: str = None, expires_in: timedelta = timedelta(minutes=5)) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": sub, "iat": now, "exp": now + expires_in},
        key or settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


# ---------- health ----------

def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


# ---------- registration ----------

def test_register_success_returns_safe_fields(client, user_payload):
    res = client.post("/auth/register", json=user_payload)
    assert res.status_code == 201
    body = res.json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.com"
    assert "id" in body
    assert "password" not in body
    assert "hashed_password" not in body
    assert "password_hash" not in body


def test_register_normalizes_email_to_lowercase(client, user_payload):
    res = client.post("/auth/register", json={**user_payload, "email": "Alice@Example.COM"})
    assert res.status_code == 201
    assert res.json()["email"] == "alice@example.com"


def test_register_stores_argon2_hash_not_plaintext(client, user_payload):
    client.post("/auth/register", json=user_payload)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "alice"))
    assert user.hashed_password != user_payload["password"]
    assert user.hashed_password.startswith("$argon2")


def test_register_duplicate_username_returns_409(client, registered_user, user_payload):
    other = {**user_payload, "email": "other@example.com"}
    assert client.post("/auth/register", json=other).status_code == 409


def test_register_duplicate_email_returns_409(client, registered_user, user_payload):
    other = {**user_payload, "username": "bob"}
    assert client.post("/auth/register", json=other).status_code == 409


def test_register_duplicate_email_is_case_insensitive(client, registered_user, user_payload):
    other = {**user_payload, "username": "bob", "email": "ALICE@Example.com"}
    assert client.post("/auth/register", json=other).status_code == 409


def test_register_validation_errors_return_422(client, user_payload):
    bad_payloads = [
        {**user_payload, "password": "short"},
        {**user_payload, "username": "ab"},
        {**user_payload, "username": "bad name!"},
        {**user_payload, "email": "not-an-email"},
        {"username": "alice"},
    ]
    for payload in bad_payloads:
        assert client.post("/auth/register", json=payload).status_code == 422


# ---------- login ----------

def test_login_success_returns_token(client, registered_user, user_payload):
    res = client.post(
        "/auth/login",
        json={"username": "alice", "password": user_payload["password"]},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["token_type"] == "bearer"
    payload = jwt.decode(
        body["access_token"], settings.secret_key, algorithms=[settings.jwt_algorithm]
    )
    assert payload["sub"] == str(registered_user["id"])
    assert "exp" in payload


def test_login_failures_share_identical_401(client, registered_user):
    wrong_password = client.post(
        "/auth/login", json={"username": "alice", "password": "wrong-password"}
    )
    unknown_user = client.post(
        "/auth/login", json={"username": "nobody", "password": "wrong-password"}
    )
    assert wrong_password.status_code == 401
    assert unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


# ---------- /auth/me and token validation ----------

def test_me_with_valid_token(client, auth_headers):
    res = client.get("/auth/me", headers=auth_headers)
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.com"
    assert "hashed_password" not in body


def test_me_without_token_returns_401(client):
    assert client.get("/auth/me").status_code == 401


def test_me_with_malformed_token_returns_401(client):
    res = client.get("/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert res.status_code == 401


def test_me_with_wrong_signature_returns_401(client, registered_user):
    token = _make_token(str(registered_user["id"]), key="a-different-secret-key-0123456789abcdef")
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_me_with_expired_token_returns_401(client, registered_user):
    token = _make_token(str(registered_user["id"]), expires_in=timedelta(minutes=-1))
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_me_with_token_for_deleted_user_returns_401(client):
    token = _make_token("99999")
    res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


# ---------- email normalization ----------

def test_register_strips_and_lowercases_padded_email(client, user_payload):
    res = client.post(
        "/auth/register", json={**user_payload, "email": "  Alice@Example.COM \t"}
    )
    assert res.status_code == 201
    assert res.json()["email"] == "alice@example.com"


def test_register_padded_duplicate_email_returns_409(client, registered_user, user_payload):
    other = {**user_payload, "username": "bob", "email": "  ALICE@example.com  "}
    assert client.post("/auth/register", json=other).status_code == 409


def test_register_padded_invalid_email_returns_422(client, user_payload):
    res = client.post("/auth/register", json={**user_payload, "email": "  not-an-email  "})
    assert res.status_code == 422


def test_register_non_string_email_returns_422(client, user_payload):
    res = client.post("/auth/register", json={**user_payload, "email": 12345})
    assert res.status_code == 422