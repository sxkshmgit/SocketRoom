import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from starlette.concurrency import run_in_threadpool
from pydantic import ValidationError
from app.config import settings
from app.connections import ConnectionManager
from app.database import SessionLocal
from app.models import User
from app.schemas import IncomingMessage, OutgoingMessage
from app.security import decode_access_token

router = APIRouter(tags=["websocket"])

AUTH_TIMEOUT_SECONDS = 10


manager = ConnectionManager(send_timeout=settings.ws_send_timeout_seconds)


def _get_user(user_id: int) -> User | None:
    with SessionLocal() as db:
        return db.get(User, user_id)


async def authenticate(websocket: WebSocket) -> User | None:
    """Expect {"type": "auth", "token": "<jwt>"} as the first message."""
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), AUTH_TIMEOUT_SECONDS)
        message = json.loads(raw)
    except (asyncio.TimeoutError, KeyError, ValueError):
        # KeyError: binary frame (no "text" key). ValueError covers JSONDecodeError
        # and other decoding errors.
        return None

    if not isinstance(message, dict) or message.get("type") != "auth":
        return None

    token = message.get("token")
    if not isinstance(token, str):
        return None

    user_id = decode_access_token(token)
    if user_id is None:
        return None

    return await run_in_threadpool(_get_user, user_id)


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        user = await authenticate(websocket)
        if user is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        manager.connect(websocket)
        try:
            while True:
                event = await websocket.receive()
                if event["type"] == "websocket.disconnect":
                    break
                text = event.get("text")
                if text is None:
                    await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA)
                    break
                try:
                    incoming = IncomingMessage.model_validate_json(text)
                except ValidationError:
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    break
                manager.broadcast(
                    OutgoingMessage(
                        sender=user.username, content=incoming.content
                    ).model_dump_json()
                )
        finally:
            manager.disconnect(websocket)
    except WebSocketDisconnect:
        pass