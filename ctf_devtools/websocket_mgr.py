"""WebSocket client connection, frame monitor, and frame sender."""
import asyncio
from datetime import datetime
from typing import List, Callable, Optional
import websockets
from .flags import FlagTracker

class WSFrame:
    def __init__(self, direction: str, payload: str):
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.direction = direction  # "IN" or "OUT"
        self.payload = payload

class WebSocketManager:
    def __init__(self, flag_tracker: Optional[FlagTracker] = None, on_frame: Optional[Callable[[WSFrame], None]] = None):
        self.flag_tracker = flag_tracker or FlagTracker()
        self.on_frame = on_frame
        self.connection = None
        self.frames: List[WSFrame] = []
        self.is_connected = False
        self._recv_task: Optional[asyncio.Task] = None

    async def connect(self, url: str):
        if self.is_connected:
            await self.disconnect()
        self.connection = await websockets.connect(url)
        self.is_connected = True
        self._recv_task = asyncio.create_task(self._listen())

    async def _listen(self):
        try:
            async for message in self.connection:
                text = str(message)
                self.flag_tracker.scan(text)
                frame = WSFrame("IN", text)
                self.frames.append(frame)
                if self.on_frame:
                    self.on_frame(frame)
        except Exception:
            pass
        finally:
            self.is_connected = False

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
