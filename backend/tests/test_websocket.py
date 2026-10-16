import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from starlette.websockets import WebSocketDisconnect

from app.config import settings
from app.database import SessionLocal
from app.models import User
from app.security import create_access_token

POLICY_VIOLATION = 1008


@pytest.fixture
def token(auth_headers):
    return auth_headers["Authorization"].removeprefix("Bearer ")


@contextmanager
def open_authed(client, token):
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": "auth", "token": token})
        yield ws


def _signed_token(sub, key=None, expires_in=timedelta(minutes=5)):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(sub), "iat": now, "exp": now + expires_in},
        key or settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def assert_rejected(ws):
    with pytest.raises(WebSocketDisconnect) as exc:
        ws.receive_text()
    assert exc.value.code == POLICY_VIOLATION


# ---------- echo behaviour (authenticated) ----------

def test_websocket_connects(client, token):
    with open_authed(client, token) as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "ping"


def test_websocket_echoes_message(client, token):
    with open_authed(client, token) as ws:
        ws.send_text("hello socketroom")
        assert ws.receive_text() == "hello socketroom"


def test_websocket_echoes_multiple_messages_in_order(client, token):
    messages = ["one", "two", "three", "", "unicode ✓"]
    with open_authed(client, token) as ws:
        for message in messages:
            ws.send_text(message)
            assert ws.receive_text() == message


def test_websocket_disconnect_is_handled_cleanly(client, token):
    with open_authed(client, token) as ws:
        ws.send_text("before disconnect")
        assert ws.receive_text() == "before disconnect"

    # The server survived the disconnect and still accepts new connections.
    with open_authed(client, token) as ws:
        ws.send_text("after reconnect")
        assert ws.receive_text() == "after reconnect"


def test_websocket_connections_are_independent(client, token):
    with (
        open_authed(client, token) as first,
        open_authed(client, token) as second,
    ):
        first.send_text("from first")
        second.send_text("from second")
        assert first.receive_text() == "from first"
        assert second.receive_text() == "from second"


def test_auth_message_is_not_echoed(client, token):
    with open_authed(client, token) as ws:
        ws.send_text("first real message")
        assert ws.receive_text() == "first real message"


# ---------- rejected first messages ----------

@pytest.mark.parametrize(
    "payload",
    [
        "hello without auth",
        "{not json",
        json.dumps(["auth"]),
        json.dumps({"type": "message", "token": "x"}),
        json.dumps({"type": "auth"}),
        json.dumps({"type": "auth", "token": 12345}),
    ],
)
def test_rejects_malformed_first_message(client, registered_user, payload):
    with client.websocket_connect("/ws") as ws:
        ws.send_text(payload)
        assert_rejected(ws)


def test_rejects_binary_first_message(client, registered_user):
    with client.websocket_connect("/ws") as ws:
        ws.send_bytes(b"\x00\x01\x02")
        assert_rejected(ws)


def test_rejects_when_no_auth_message_arrives(client, monkeypatch):
    monkeypatch.setattr("app.routers.websocket.AUTH_TIMEOUT_SECONDS", 0.1)
    with client.websocket_connect("/ws") as ws:
        assert_rejected(ws)


# ---------- rejected tokens ----------

def test_rejects_invalid_token(client, registered_user):
    with open_authed(client, "not.a.jwt") as ws:
        assert_rejected(ws)


def test_rejects_wrong_signature(client, registered_user):
    bad = _signed_token(
        registered_user["id"], key="a-different-secret-key-0123456789abcdef"
    )
    with open_authed(client, bad) as ws:
        assert_rejected(ws)


def test_rejects_expired_token(client, registered_user):
    expired = _signed_token(registered_user["id"], expires_in=timedelta(minutes=-1))
    with open_authed(client, expired) as ws:
        assert_rejected(ws)


def test_rejects_token_for_deleted_user(client, registered_user):
    stale_token = create_access_token(registered_user["id"])
    with SessionLocal() as db:
        db.delete(db.get(User, registered_user["id"]))
        db.commit()

    with open_authed(client, stale_token) as ws:
        assert_rejected(ws)


def test_token_in_query_string_is_not_accepted(client, token):
    with client.websocket_connect(f"/ws?token={token}") as ws:
        ws.send_text("hello")
        assert_rejected(ws)