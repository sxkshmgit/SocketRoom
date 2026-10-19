import asyncio
import json
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from app.schemas import MESSAGE_MAX_LENGTH

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
UNSUPPORTED_DATA = 1003
TRY_AGAIN_LATER = 1013


# ---------- helpers ----------

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

def send_msg(ws, content):
    ws.send_json({"type": "message", "content": content})


def recv_msg(ws):
    return json.loads(ws.receive_text())


def assert_msg(message, content, sender="alice"):
    assert message == {"type": "message", "sender": sender, "content": content}


@pytest.fixture
def bob_token(client):
    payload = {"username": "bob", "email": "bob@example.com", "password": "correct-horse-battery"}
    assert client.post("/auth/register", json=payload).status_code == 201
    res = client.post(
        "/auth/login", json={"username": "bob", "password": payload["password"]}
    )
    return res.json()["access_token"]

def _signed_token(sub, key=None, expires_in=timedelta(minutes=5)):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(sub), "iat": now, "exp": now + expires_in},
        key or settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def assert_rejected(ws, code=POLICY_VIOLATION):
    with pytest.raises(WebSocketDisconnect) as exc:
        ws.receive_text()
    assert exc.value.code == code


class FakeSocket:
    """Minimal stand-in for a WebSocket, used to test the manager directly."""

    def __init__(self, delay=0.0, error=None, stall=False):
        self.delay = delay
        self.error = error
        self.stall = stall
        self.received = []
        self.closed_with = None

    async def send_text(self, message):
        if self.stall:
            await asyncio.Event().wait()
        if self.error:
            raise self.error
        if self.delay:
            await asyncio.sleep(self.delay)
        self.received.append(message)

    async def close(self, code=1000):
        self.closed_with = code


async def eventually(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out waiting for condition"
        await asyncio.sleep(0.005)


# ---------- authentication ----------

def test_websocket_connects(client, token):
    with open_authed(client, token) as ws:
        send_msg(ws, "ping")
        assert_msg(recv_msg(ws), "ping")


def test_auth_message_is_not_broadcast(client, token):
    with open_authed(client, token) as ws:
        send_msg(ws, "first real message")
        assert_msg(recv_msg(ws), "first real message")

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


def test_rejected_connection_is_never_registered(client, registered_user):
    before = len(manager)
    with open_authed(client, "not.a.jwt") as ws:
        assert_rejected(ws)
    assert len(manager) == before


# ---------- messaging and broadcast (endpoint) ----------

def test_websocket_echoes_message_with_sender(client, token):
    with open_authed(client, token) as ws:
        send_msg(ws, "hello socketroom")
        assert_msg(recv_msg(ws), "hello socketroom")


def test_websocket_echoes_multiple_messages_in_order(client, token):
    messages = ["one", "two", "three", "unicode ✓"]
    with open_authed(client, token) as ws:
        for content in messages:
            send_msg(ws, content)
            assert_msg(recv_msg(ws), content)


def test_content_is_trimmed(client, token):
    with open_authed(client, token) as ws:
        send_msg(ws, "  padded \n")
        assert_msg(recv_msg(ws), "padded")


def test_content_at_max_length_is_accepted(client, token):
    content = "x" * MESSAGE_MAX_LENGTH
    with open_authed(client, token) as ws:
        send_msg(ws, content)
        assert_msg(recv_msg(ws), content)


def test_sender_is_the_authenticated_username(client, token, bob_token):
    with open_joined(client, token) as alice, open_joined(client, bob_token) as bob:
        send_msg(alice, "from alice")
        assert_msg(recv_msg(alice), "from alice", sender="alice")
        assert_msg(recv_msg(bob), "from alice", sender="alice")

        send_msg(bob, "from bob")
        assert_msg(recv_msg(alice), "from bob", sender="bob")
        assert_msg(recv_msg(bob), "from bob", sender="bob")


def test_websocket_disconnect_is_handled_cleanly(client, token):
    with open_authed(client, token) as ws:
        send_msg(ws, "before disconnect")
        assert_msg(recv_msg(ws), "before disconnect")

    # The server survived the disconnect and still accepts new connections.
    with open_authed(client, token) as ws:
        send_msg(ws, "after reconnect")
        assert_msg(recv_msg(ws), "after reconnect")


def test_broadcast_reaches_all_clients_including_sender(client, token):
    with open_joined(client, token) as first, open_joined(client, token) as second:
        send_msg(first, "hello all")
        assert_msg(recv_msg(first), "hello all")
        assert_msg(recv_msg(second), "hello all")


def test_broadcast_works_from_either_client(client, token):
    with open_joined(client, token) as first, open_joined(client, token) as second:
        send_msg(first, "from first")
        assert_msg(recv_msg(first), "from first")
        assert_msg(recv_msg(second), "from first")

        send_msg(second, "from second")
        assert_msg(recv_msg(first), "from second")
        assert_msg(recv_msg(second), "from second")


def test_alternating_senders_never_hang(client, token):
    # Regression: a shared asyncio.Lock hung when consecutive broadcasts came
    # from connections running on different event loops.
    with open_joined(client, token) as first, open_joined(client, token) as second:
        for i in range(25):
            sender, other = (first, second) if i % 2 == 0 else (second, first)
            send_msg(sender, f"m{i}")
            assert_msg(recv_msg(sender), f"m{i}")
            assert_msg(recv_msg(other), f"m{i}")


def test_all_clients_see_the_same_order(client, token):
    with (
        open_joined(client, token) as a,
        open_joined(client, token) as b,
        open_joined(client, token) as c,
    ):
        for ws, name in ((a, "a"), (b, "b"), (c, "c")):
            send_msg(ws, name)
        seen = [[recv_msg(ws)["content"] for _ in range(3)] for ws in (a, b, c)]
    assert seen[0] == seen[1] == seen[2]
    assert sorted(seen[0]) == ["a", "b", "c"]


def test_disconnected_client_is_removed_and_others_keep_working(client, token):
    with open_joined(client, token) as first:
        with open_joined(client, token):
            assert len(manager) == 2
        wait_for(lambda: len(manager) == 1)

        send_msg(first, "still here")
        assert_msg(recv_msg(first), "still here")
    wait_for(lambda: len(manager) == 0)


def test_binary_frame_after_auth_closes_with_1003_and_cleans_up(client, token):
    with open_joined(client, token) as ws:
        ws.send_bytes(b"\x00\x01")
        assert_rejected(ws, code=UNSUPPORTED_DATA)
    wait_for(lambda: len(manager) == 0)


def test_server_keeps_working_after_a_binary_frame(client, token):
    with open_joined(client, token) as bad:
        bad.send_bytes(b"\x00")
        assert_rejected(bad, code=UNSUPPORTED_DATA)

    with open_joined(client, token) as ws:
        send_msg(ws, "still fine")
        assert_msg(recv_msg(ws), "still fine")


# ---------- message protocol validation ----------

INVALID_MESSAGES = {
    "malformed_json": "{not json",
    "plain_text": "just text",
    "json_array": json.dumps(["message"]),
    "missing_content": json.dumps({"type": "message"}),
    "missing_type": json.dumps({"content": "hi"}),
    "non_string_content": json.dumps({"type": "message", "content": 123}),
    "invalid_type": json.dumps({"type": "typing", "content": "hi"}),
    "forged_sender": json.dumps({"type": "message", "content": "hi", "sender": "mallory"}),
    "empty_content": json.dumps({"type": "message", "content": ""}),
    "whitespace_only": json.dumps({"type": "message", "content": "  \t\n "}),
    "too_long": json.dumps({"type": "message", "content": "x" * (MESSAGE_MAX_LENGTH + 1)}),
}


@pytest.mark.parametrize("payload", INVALID_MESSAGES.values(), ids=INVALID_MESSAGES.keys())
def test_invalid_message_closes_with_1008_and_cleans_up(client, token, payload):
    with open_joined(client, token) as ws:
        ws.send_text(payload)
        assert_rejected(ws)
    wait_for(lambda: len(manager) == 0)


def test_invalid_message_is_not_broadcast_and_others_keep_working(client, token):
    forged = INVALID_MESSAGES["forged_sender"]
    with open_joined(client, token) as bad, open_joined(client, token) as good:
        bad.send_text(forged)
        assert_rejected(bad)
        wait_for(lambda: len(manager) == 1)

        send_msg(good, "legit")
        # The first thing `good` sees is its own legit message, not the forged one.
        assert_msg(recv_msg(good), "legit")


# ---------- connection manager (unit) ----------

def test_manager_delivers_to_all_clients():
    async def scenario():
        local = ConnectionManager()
        a, b = FakeSocket(), FakeSocket()
        local.connect(a)
        local.connect(b)
        local.broadcast("hi")
        await eventually(lambda: a.received == ["hi"] and b.received == ["hi"])

    asyncio.run(scenario())


def test_manager_drops_client_whose_send_fails():
    async def scenario():
        local = ConnectionManager()
        broken, live = FakeSocket(error=RuntimeError("closed")), FakeSocket()
        local.connect(broken)
        local.connect(live)
        local.broadcast("hi")
        await eventually(lambda: live.received == ["hi"] and len(local) == 1)
        await eventually(lambda: broken.closed_with == TRY_AGAIN_LATER)

    asyncio.run(scenario())


def test_stalled_client_is_dropped_and_does_not_block_others():
    async def scenario():
        local = ConnectionManager(send_timeout=0.05)
        stalled, live = FakeSocket(stall=True), FakeSocket()
        local.connect(stalled)
        local.connect(live)

        started = time.monotonic()
        local.broadcast("1")
        local.broadcast("2")
        await eventually(lambda: live.received == ["1", "2"])
        assert time.monotonic() - started < 1.0

        await eventually(lambda: len(local) == 1)
        await eventually(lambda: stalled.closed_with == TRY_AGAIN_LATER)

    asyncio.run(scenario())


def test_client_with_full_queue_is_dropped():
    async def scenario():
        local = ConnectionManager(send_timeout=30, max_queue_size=2)
        stalled = FakeSocket(stall=True)
        local.connect(stalled)
        for i in range(10):
            local.broadcast(str(i))
        await eventually(lambda: len(local) == 0)
        await eventually(lambda: stalled.closed_with == TRY_AGAIN_LATER)

    asyncio.run(scenario())


def test_disconnect_stops_delivery_and_leaves_no_tasks_behind():
    async def scenario():
        local = ConnectionManager()
        gone, live = FakeSocket(), FakeSocket()
        local.connect(gone)
        local.connect(live)
        local.disconnect(gone)
        assert len(local) == 1

        local.broadcast("hi")
        await eventually(lambda: live.received == ["hi"])
        assert gone.received == []

        local.disconnect(live)
        await eventually(lambda: len(asyncio.all_tasks()) == 1)  # only this one

    asyncio.run(scenario())


def test_concurrent_broadcasts_keep_one_order_for_every_client():
    async def scenario():
        local = ConnectionManager()
        slow, fast = FakeSocket(delay=0.001), FakeSocket()
        local.connect(slow)
        local.connect(fast)

        def send_batch(name):
            for i in range(25):
                local.broadcast(f"{name}-{i}")

        await asyncio.gather(*(asyncio.to_thread(send_batch, n) for n in "abcd"))
        await eventually(lambda: len(slow.received) == 100 and len(fast.received) == 100)

        assert slow.received == fast.received
        for name in "abcd":
            mine = [m for m in fast.received if m.startswith(f"{name}-")]
            assert mine == [f"{name}-{i}" for i in range(25)]

    asyncio.run(scenario())