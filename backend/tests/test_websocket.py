import asyncio
import json
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from starlette.websockets import WebSocketDisconnect

from app.config import settings
from app.connections import ConnectionManager
from app.database import SessionLocal
from app.models import User
from app.routers.websocket import manager
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
def wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out waiting for condition"
        time.sleep(0.01)


@contextmanager
def open_joined(client, token):
    """Like open_authed, but waits until the server has registered the socket."""
    before = len(manager)
    with open_authed(client, token) as ws:
        wait_for(lambda: len(manager) > before)
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


def test_broadcast_reaches_all_clients_including_sender(client, token):
    with open_joined(client, token) as first, open_joined(client, token) as second:
        first.send_text("hello all")
        assert first.receive_text() == "hello all"
        assert second.receive_text() == "hello all"


def test_broadcast_works_from_either_client(client, token):
    with open_joined(client, token) as first, open_joined(client, token) as second:
        first.send_text("from first")
        assert first.receive_text() == "from first"
        assert second.receive_text() == "from first"

        second.send_text("from second")
        assert first.receive_text() == "from second"
        assert second.receive_text() == "from second"


def test_disconnected_client_is_removed_and_others_keep_working(client, token):
    with open_joined(client, token) as first:
        with open_joined(client, token):
            assert len(manager) == 2
        wait_for(lambda: len(manager) == 1)

        first.send_text("still here")
        assert first.receive_text() == "still here"
    wait_for(lambda: len(manager) == 0)


def test_rejected_connection_is_never_registered(client, registered_user):
    before = len(manager)
    with open_authed(client, "not.a.jwt") as ws:
        assert_rejected(ws)
    assert len(manager) == before


class _StaleSocket:
    async def send_text(self, message):
        raise RuntimeError("connection closed")


class _LiveSocket:
    def __init__(self):
        self.sent = []

    async def send_text(self, message):
        self.sent.append(message)


def test_broadcast_drops_stale_connections_and_still_reaches_live_ones():
    local = ConnectionManager()
    stale, live = _StaleSocket(), _LiveSocket()
    local.connect(stale)
    local.connect(live)

    asyncio.run(local.broadcast("hi"))

    assert live.sent == ["hi"]
    assert len(local) == 1
class _DelayedSocket:
    def __init__(self, delays):
        self.delays = delays
        self.received = []

    async def send_text(self, message):
        await asyncio.sleep(self.delays.get(message, 0))
        self.received.append(message)


def test_concurrent_broadcasts_arrive_in_same_order_for_all_clients():
    local = ConnectionManager()
    slow_on_first = _DelayedSocket({"1": 0.05})
    fast = _DelayedSocket({})
    local.connect(slow_on_first)
    local.connect(fast)

    async def run():
        await asyncio.gather(local.broadcast("1"), local.broadcast("2"))

    asyncio.run(run())

    assert slow_on_first.received == ["1", "2"]
    assert fast.received == ["1", "2"]

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