from __future__ import annotations
"""Central HTTP Network Traffic Logger tracking requests and responses across all tools."""
from dataclasses import dataclass
import time
from typing import Dict, List, Optional

@dataclass
class NetworkEntry:
    id: int
    timestamp: str
    method: str
    url: str
    status_code: int
    bytes_len: int
    elapsed_ms: float
    req_headers: Dict[str, str]
    req_body: str
    resp_headers: Dict[str, str]
    resp_body: str

class NetworkLogger:
    """Records and indexes all HTTP traffic passing through CTF DevTools."""
    def __init__(self, max_entries: int = 300):
        self.entries: List[NetworkEntry] = []
        self._next_id = 1
        self.max_entries = max_entries

    def log(
        self,
        method: str,
        url: str,
        status_code: int,
        bytes_len: int,
        elapsed_ms: float,
        req_headers: Optional[Dict[str, str]] = None,
        req_body: str = "",
        resp_headers: Optional[Dict[str, str]] = None,
        resp_body: str = "",
    ) -> NetworkEntry:
        entry = NetworkEntry(
            id=self._next_id,
            timestamp=time.strftime("%H:%M:%S"),
            method=method.upper(),
            url=url,
            status_code=status_code,
            bytes_len=bytes_len,
            elapsed_ms=round(elapsed_ms, 2),
            req_headers=dict(req_headers or {}),
            req_body=req_body or "",
            resp_headers=dict(resp_headers or {}),
            resp_body=resp_body or "",
        )
        self._next_id += 1
        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            self.entries.pop(0)
        return entry

    def clear(self):
        self.entries.clear()
        self._next_id = 1
