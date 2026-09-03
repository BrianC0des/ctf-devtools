from __future__ import annotations
"""Automated CTF reconnaissance, sensitive file probing, and tech stack fingerprinting."""
import asyncio
import random
import string
import urllib.parse
from dataclasses import dataclass
from typing import List, Dict, Optional, Callable
import httpx
from .flags import FlagTracker

CTF_PROBE_PATHS = [
    # Information leaks
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    # Source control & environment
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.backup",
    "/.DS_Store",
    # Config & build
    "/package.json",
    "/composer.json",
    "/Dockerfile",
    "/docker-compose.yml",
    "/web.config",
    # Backups & archives
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/index.php.bak",
    "/app.py~",
    # Administration & debug
    "/admin",
    "/admin/",
    "/administrator",
    "/dashboard",
    "/panel",
    "/console",
    "/debug",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
]

@dataclass
class ScanResult:
    path: str
    url: str
    status_code: int
    content_length: int
    content_type: str
    snippet: str
    flags: List[str]
    is_interesting: bool
    body: str = ""

class CTFScanner:
    def __init__(self, base_url: str, flag_tracker: Optional[FlagTracker] = None, timeout: float = 6.0, cookie_storage: Optional[Any] = None):
        self.base_url = base_url.rstrip('/')
        self.flag_tracker = flag_tracker or FlagTracker()
        self.timeout = timeout
        self.cookie_storage = cookie_storage
        self.results: List[ScanResult] = []
        self.tech_stack: Dict[str, str] = {}
        self.soft_404_len: Optional[int] = None

    async def check_soft_404(self, client: httpx.AsyncClient):
        rand_slug = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        test_url = f"{self.base_url}/nonexistent_{rand_slug}"
        try:
            r = await client.get(test_url)
            if r.status_code == 200:
                self.soft_404_len = len(r.content)
        except Exception:
            pass

    async def probe_single(self, client: httpx.AsyncClient, path: str) -> Optional[ScanResult]:
        url = f"{self.base_url}{path}"
        try:
            r = await client.get(url, follow_redirects=False)
            content = r.text
            length = len(r.content)
            
            # Check for soft 404
            if self.soft_404_len is not None and abs(length - self.soft_404_len) < 20 and r.status_code == 200:
                return None

            flags = self.flag_tracker.scan(content)
            interesting = (
                r.status_code in [200, 301, 302, 401, 403, 500] and
                r.status_code != 404
            )
            
            snippet = content[:150].replace('\n', ' ').strip()
            return ScanResult(
                path=path,
                url=url,
                status_code=r.status_code,
                content_length=length,
                content_type=r.headers.get("content-type", ""),
                snippet=snippet,
                flags=flags,
                is_interesting=interesting,
                body=content
            )
        except Exception:
            return None

    async def scan_all(self, on_progress: Optional[Callable[[int, int, ScanResult], None]] = None) -> List[ScanResult]:
        headers = {"User-Agent": "CTF-DevTools/1.0"}
        if self.cookie_storage:
            headers = self.cookie_storage.get_merged_headers(headers)
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(timeout=self.timeout, limits=limits, verify=False, headers=headers) as client:
            # Fingerprint base URL
            try:
                base_resp = await client.get(self.base_url, follow_redirects=True)
                for header in ["server", "x-powered-by", "x-backend-server", "access-control-allow-origin"]:
                    if header in base_resp.headers:
                        self.tech_stack[header] = base_resp.headers[header]
                if self.cookie_storage:
                    for h in getattr(base_resp, "history", []):
                        for sc in h.headers.get_list("set-cookie"):
                            self.cookie_storage.parse_set_cookie(sc)
                    for sc in base_resp.headers.get_list("set-cookie"):
                        self.cookie_storage.parse_set_cookie(sc)
            except Exception:
                pass

            await self.check_soft_404(client)

            total = len(CTF_PROBE_PATHS)
            self.results = []
            
            async def worker(path, idx):
                res = await self.probe_single(client, path)
                if res and res.is_interesting:
                    self.results.append(res)
                if on_progress and res:
                    on_progress(idx, total, res)

            tasks = [worker(path, idx + 1) for idx, path in enumerate(CTF_PROBE_PATHS)]
            await asyncio.gather(*tasks)

        return sorted(self.results, key=lambda x: (0 if x.status_code == 200 else 1, x.status_code))
