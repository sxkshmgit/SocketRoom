import asyncio
import contextlib
import threading

from fastapi import WebSocket, status


class _Client:
    """One connection: its own loop, bounded outbound queue and writer task."""

    __slots__ = ("websocket", "loop", "queue", "task")

    def __init__(self, websocket: WebSocket, max_queue_size: int) -> None:
        self.websocket = websocket
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=max_queue_size)
        self.task: asyncio.Task | None = None


class ConnectionManager:
    """Tracks authenticated WebSocket connections and broadcasts to them.

    Every client has a FIFO queue drained by its own writer task, so one slow
    client never delays the others. Broadcasts are handed to each client's own
    event loop with call_soon_threadsafe while holding a plain threading lock
    (never held across an await). That keeps one global order for every client
    and works whether connections share a loop (uvicorn) or not (TestClient).
    """

    def __init__(self, send_timeout: float = 5.0, max_queue_size: int = 100) -> None:
        self._send_timeout = send_timeout
        self._max_queue_size = max_queue_size
        self._clients: dict[WebSocket, _Client] = {}
        self._lock = threading.RLock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._clients)

    def connect(self, websocket: WebSocket) -> None:
        """Register a socket. Must be called from the socket's own event loop."""
        client = _Client(websocket, self._max_queue_size)
        client.task = client.loop.create_task(self._writer(client))
        with self._lock:
            self._clients[websocket] = client

    def disconnect(self, websocket: WebSocket) -> None:
        client = self._remove(websocket)
        if client is not None and client.task is not None:
            with contextlib.suppress(RuntimeError):  # the client's loop already closed
                client.loop.call_soon_threadsafe(client.task.cancel)

    def broadcast(self, message: str) -> None:
        """Queue a message for every client. Never blocks and never raises."""
        with self._lock:
            for client in list(self._clients.values()):
                try:
                    client.loop.call_soon_threadsafe(self._enqueue, client, message)
                except RuntimeError:  # the client's loop is closed
                    self._clients.pop(client.websocket, None)

    def _remove(self, websocket: WebSocket) -> _Client | None:
        with self._lock:
            return self._clients.pop(websocket, None)

    def _enqueue(self, client: _Client, message: str) -> None:
        # Runs on the client's own loop.
        try:
            client.queue.put_nowait(message)
        except asyncio.QueueFull:
            # Client can't keep up: drop it instead of buffering without limit.
            self.disconnect(client.websocket)
            client.loop.create_task(self._close(client.websocket))

    async def _writer(self, client: _Client) -> None:
        try:
            while True:
                message = await client.queue.get()
                await asyncio.wait_for(
                    client.websocket.send_text(message), self._send_timeout
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Send failed or timed out: forget the client and close its socket.
            self._remove(client.websocket)
            await self._close(client.websocket)

    async def _close(self, websocket: WebSocket) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                websocket.close(code=status.WS_1013_TRY_AGAIN_LATER),
                self._send_timeout,
            )