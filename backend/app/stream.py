"""WebSocket stream broadcaster for real-time scenario and system event animations."""

import asyncio
import json
import logging
from typing import Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter(tags=["stream"])


class StreamBroadcaster:
    """Thread-safe WebSocket broadcaster for real-time console streaming."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the running asyncio event loop."""
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection and track it."""
        await websocket.accept()
        self._connections.add(websocket)
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        logger.info("WebSocket client connected. Active clients: %d", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket."""
        self._connections.discard(websocket)
        logger.info("WebSocket client disconnected. Active clients: %d", len(self._connections))

    async def broadcast_async(self, msg_type: str, data: Any) -> None:
        """Broadcast payload to all active WebSocket connections asynchronously."""
        if not self._connections:
            return

        payload = json.dumps({"type": msg_type, "data": data}, default=str)
        dead: list[WebSocket] = []

        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self._connections.discard(ws)

    def broadcast_sync(self, msg_type: str, data: Any) -> None:
        """Thread-safe sync dispatch to broadcast payload on the event loop."""
        if not self._connections:
            return

        loop = self._loop
        if loop is None or not loop.is_running():
            try:
                loop = asyncio.get_running_loop()
                self._loop = loop
            except RuntimeError:
                try:
                    loop = asyncio.get_event_loop()
                    self._loop = loop
                except RuntimeError:
                    loop = None

        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast_async(msg_type, data), loop)


_broadcaster = StreamBroadcaster()


def get_broadcaster() -> StreamBroadcaster:
    """Return singleton StreamBroadcaster instance."""
    return _broadcaster


@router.websocket("/v1/stream")
async def websocket_stream_endpoint(websocket: WebSocket) -> None:
    """Live stream WebSocket endpoint broadcasting events, alerts, sinkholes, and scenario steps."""
    broadcaster = get_broadcaster()
    await broadcaster.connect(websocket)
    try:
        while True:
            # Keep connection alive; wait for incoming messages or ping/pong
            data = await websocket.receive_text()
            # Echo or ignore client messages
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong", "data": {}}))
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception as exc:
        logger.debug("WebSocket connection closed with error: %s", exc)
        broadcaster.disconnect(websocket)
