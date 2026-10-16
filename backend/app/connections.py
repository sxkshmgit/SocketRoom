import asyncio

from fastapi import WebSocket


class ConnectionManager:
    """Tracks authenticated WebSocket connections and broadcasts to them."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        # Serializes broadcasts so every client sees messages in the same order.
        self._broadcast_lock = asyncio.Lock()

    def __len__(self) -> int:
        return len(self._connections)

    def connect(self, websocket: WebSocket) -> None:
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    async def broadcast(self, message: str) -> None:
        async with self._broadcast_lock:
            connections = list(self._connections)
            results = await asyncio.gather(
                *(ws.send_text(message) for ws in connections),
                return_exceptions=True,
            )
            # A failed send means the peer is gone; drop it so it isn't retried.
            for ws, result in zip(connections, results):
                if isinstance(result, Exception):
                    self.disconnect(ws)