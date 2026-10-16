def test_websocket_connects(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "ping"


def test_websocket_echoes_message(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_text("hello socketroom")
        assert ws.receive_text() == "hello socketroom"


def test_websocket_echoes_multiple_messages_in_order(client):
    messages = ["one", "two", "three", "", "unicode ✓"]
    with client.websocket_connect("/ws") as ws:
        for message in messages:
            ws.send_text(message)
            assert ws.receive_text() == message


def test_websocket_disconnect_is_handled_cleanly(client):
    with client.websocket_connect("/ws") as ws:
        ws.send_text("before disconnect")
        assert ws.receive_text() == "before disconnect"

    # The server survived the disconnect and still accepts new connections.
    with client.websocket_connect("/ws") as ws:
        ws.send_text("after reconnect")
        assert ws.receive_text() == "after reconnect"


def test_websocket_connections_are_independent(client):
    with (
        client.websocket_connect("/ws") as first,
        client.websocket_connect("/ws") as second,
    ):
        first.send_text("from first")
        second.send_text("from second")
        assert first.receive_text() == "from first"
        assert second.receive_text() == "from second"