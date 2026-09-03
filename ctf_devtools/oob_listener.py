"""Local Out-Of-Band (OOB) HTTP callback listener for Blind SSRF and XSS."""
import asyncio
from datetime import datetime
from typing import List, Dict, Callable, Optional

class OOBRequest:
    def __init__(self, client_ip: str, method: str, path: str, headers: Dict[str, str], body: str):
        self.timestamp = datetime.now().strftime("%H:%M:%S")
        self.client_ip = client_ip
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body

class OOBListener:
    def __init__(self, port: int = 9999, on_hit: Optional[Callable[[OOBRequest], None]] = None):
        self.port = port
        self.on_hit = on_hit
        self.hits: List[OOBRequest] = []
        self.server: Optional[asyncio.Server] = None
        self.is_running = False

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            client_ip = writer.get_extra_info('peername')[0]
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                await writer.wait_closed()
                return

            line_str = request_line.decode('utf-8', errors='replace').strip()
            parts = line_str.split()
            method = parts[0] if len(parts) > 0 else "UNKNOWN"
            path = parts[1] if len(parts) > 1 else "/"

            headers = {}
            content_length = 0
            while True:
                h_line = await reader.readline()
                if not h_line or h_line == b'\r\n' or h_line == b'\n':
                    break
                decoded_h = h_line.decode('utf-8', errors='replace').strip()
                if ':' in decoded_h:
                    k, v = decoded_h.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
                    if k.strip().lower() == 'content-length':
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            pass

            body = ""
            if content_length > 0:
                raw_body = await reader.readexactly(content_length)
                body = raw_body.decode('utf-8', errors='replace')

            hit = OOBRequest(
                client_ip=client_ip,
                method=method,
                path=path,
                headers=headers,
                body=body
            )
            self.hits.append(hit)
            if self.on_hit:
                self.on_hit(hit)

            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"OK\n"
            )
            writer.write(response)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        if self.is_running:
            return
        self.server = await asyncio.start_server(self._handle_client, '0.0.0.0', self.port)
        self.is_running = True

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.is_running = False
