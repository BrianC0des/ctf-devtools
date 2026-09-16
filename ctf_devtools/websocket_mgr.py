from __future__ import annotations
"""WebSocket client connection, frame monitor, and frame sender."""
import asyncio
from datetime import datetime
from typing import List, Callable, Optional, Any
import websockets
from .flags import FlagTracker

class WSFrame:
    def __init__(self, direction: str, payload: str):
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.direction = direction  # "IN" or "OUT"
        self.payload = payload
        self.data = payload

class WebSocketManager:
    def __init__(
        self,
        *args,
        url: Optional[str] = None,
        flag_tracker: Optional[Any] = None,
        on_frame: Optional[Callable[[WSFrame], None]] = None,
        **kwargs
    ):
        self.url = url or ""
        self.flag_tracker = flag_tracker
        self.on_frame = on_frame

        # Handle positional args for backward compatibility
        if len(args) >= 1:
            first = args[0]
            if isinstance(first, str):
                self.url = first
            elif hasattr(first, "scan") or isinstance(first, FlagTracker):
                self.flag_tracker = first
            elif callable(first):
                self.on_frame = first
        if len(args) >= 2:
            second = args[1]
            if hasattr(second, "scan") or isinstance(second, FlagTracker):
                self.flag_tracker = second
            elif callable(second):
                self.on_frame = second

        if "target_or_tracker" in kwargs:
            tot = kwargs["target_or_tracker"]
            if isinstance(tot, str) and not self.url:
                self.url = tot
            elif hasattr(tot, "scan") and not self.flag_tracker:
                self.flag_tracker = tot

        self.flag_tracker = self.flag_tracker or FlagTracker()

        self.connection = None
        self.frames: List[WSFrame] = []
        self.is_connected = False
        self._recv_task: Optional[asyncio.Task] = None
        self._frame_queue: asyncio.Queue = asyncio.Queue()

    @property
    def connected(self) -> bool:
        return self.is_connected

    async def connect(self, url: Optional[str] = None) -> bool:
        target_url = url or self.url
        if not target_url:
            return False
        self.url = target_url
        if self.is_connected:
            await self.disconnect()
        try:
            self.connection = await websockets.connect(target_url)
            self.is_connected = True
            self._recv_task = asyncio.create_task(self._listen())
            return True
        except Exception:
            self.is_connected = False
            return False

    async def _listen(self):
        try:
            async for message in self.connection:
                text = str(message)
                self.flag_tracker.scan(text)
                frame = WSFrame("IN", text)
                self.frames.append(frame)
                await self._frame_queue.put(frame)
                if self.on_frame:
                    self.on_frame(frame)
        except Exception:
            pass
        finally:
            self.is_connected = False

    async def receive_frame(self, timeout: float = 1.0) -> Optional[WSFrame]:
        try:
            return await asyncio.wait_for(self._frame_queue.get(), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return None

    async def send_frame(self, message: str):
        await self.send(message)

    async def send(self, message: str):
        if not self.is_connected or not self.connection:
            raise RuntimeError("WebSocket is not connected")
        await self.connection.send(message)
        frame = WSFrame("OUT", message)
        self.frames.append(frame)
        if self.on_frame:
            self.on_frame(frame)

    async def disconnect(self):
        if self._recv_task:
            self._recv_task.cancel()
        if self.connection:
            await self.connection.close()
        self.is_connected = False
