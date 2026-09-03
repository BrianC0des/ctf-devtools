from __future__ import annotations
"""Request composer, repeater, intruder/fuzzer, and response diff engine."""
import asyncio
import difflib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import httpx
from .flags import FlagTracker

@dataclass
class RepeaterResponse:
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    content_length: int
    flags: List[str] = field(default_factory=list)

@dataclass
class FuzzResult:
    payload: str
    status_code: int
    length: int
    elapsed_ms: float
    flags: List[str]

FUZZ_MARKERS = ["§FUZZ§", "§fuzz§", "{FUZZ}", "{fuzz}", "FUZZ", "fzz"]

def replace_fuzz_marker(text: str, replacement: str) -> str:
    """Replaces any supported fuzz marker (FUZZ, fzz, §FUZZ§, {FUZZ}) with the replacement string."""
    if not text:
        return text
    res = text
    for m in FUZZ_MARKERS:
        if m in res:
            res = res.replace(m, replacement)
    return res

def has_fuzz_marker(text: str) -> bool:
    """Checks if text contains any supported fuzz marker."""
    return any(m in text for m in FUZZ_MARKERS)

class RepeaterEngine:
    def __init__(self, flag_tracker: Optional[FlagTracker] = None, cookie_storage: Optional[Any] = None, network_logger: Optional[Any] = None):
        self.flag_tracker = flag_tracker or FlagTracker()
        self.cookie_storage = cookie_storage
        self.network_logger = network_logger

    async def send_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str = "",
        timeout: float = 10.0,
        follow_redirects: bool = True
    ) -> RepeaterResponse:
        client_cookies: Dict[str, str] = {}
        cleaned_headers: Dict[str, str] = {}

        # Extract explicit Cookie header into dict so httpx maintains it across redirects
        for k, v in headers.items():
            if k.lower() == "cookie":
                for part in v.split(";"):
                    if "=" in part:
                        ck, cv = part.strip().split("=", 1)
                        client_cookies[ck.strip()] = cv.strip()
            else:
                cleaned_headers[k] = v

        # Merge global cookies and headers from cookie_storage
        if self.cookie_storage:
            for ck, cdata in self.cookie_storage.cookies.items():
                if ck not in client_cookies:
                    client_cookies[ck] = cdata["value"]
            cleaned_headers = self.cookie_storage.get_merged_headers(cleaned_headers)
            cleaned_headers = {k: v for k, v in cleaned_headers.items() if k.lower() != "cookie"}

        start = time.perf_counter()
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=follow_redirects, cookies=client_cookies) as client:
            try:
                r = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=cleaned_headers,
                    content=body.encode('utf-8') if body else None
                )
                if self.cookie_storage:
                    # Capture Set-Cookie headers from redirect chain (e.g. 302 Found)
                    for hist_resp in getattr(r, "history", []):
                        for sc in hist_resp.headers.get_list("set-cookie"):
                            self.cookie_storage.parse_set_cookie(sc)
                    # Capture Set-Cookie from final response
                    for sc in r.headers.get_list("set-cookie"):
                        self.cookie_storage.parse_set_cookie(sc)
                    # Sync any remaining cookies from client jar
                    for ck, cv in client.cookies.items():
                        if ck not in self.cookie_storage.cookies:
                            self.cookie_storage.set_cookie(ck, cv)
                elapsed = (time.perf_counter() - start) * 1000
                text = r.text
                flags = self.flag_tracker.scan(text)
                if self.network_logger:
                    self.network_logger.log(
                        method=method,
                        url=url,
                        status_code=r.status_code,
                        bytes_len=len(r.content),
                        elapsed_ms=elapsed,
                        req_headers=headers,
                        req_body=body,
                        resp_headers=dict(r.headers),
                        resp_body=text,
                    )
                return RepeaterResponse(
                    status_code=r.status_code,
                    headers=dict(r.headers),
                    body=text,
                    elapsed_ms=round(elapsed, 2),
                    content_length=len(r.content),
                    flags=flags
                )
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                return RepeaterResponse(
                    status_code=0,
                    headers={},
                    body=f"[!] Request Error: {e}",
                    elapsed_ms=round(elapsed, 2),
                    content_length=0,
                    flags=[]
                )

    async def run_fuzzer(
        self,
        method: str,
        url_template: str,
        headers_template: Dict[str, str],
        body_template: str,
        payloads: List[str],
        concurrency: int = 10,
        follow_redirects: bool = True
    ) -> List[FuzzResult]:
        results = []
        sem = asyncio.Semaphore(concurrency)

        async def worker(payload: str):
            async with sem:
                u = replace_fuzz_marker(url_template, payload)
                b = replace_fuzz_marker(body_template, payload)
                h = {k: replace_fuzz_marker(v, payload) for k, v in headers_template.items()}
                res = await self.send_request(method, u, h, b, follow_redirects=follow_redirects)
                results.append(FuzzResult(
                    payload=payload,
                    status_code=res.status_code,
                    length=res.content_length,
                    elapsed_ms=res.elapsed_ms,
                    flags=res.flags
                ))

        tasks = [worker(p) for p in payloads]
        await asyncio.gather(*tasks)

        def sort_key(x: FuzzResult):
            flag_prio = 0 if x.flags else 1
            try:
                num = int(x.payload)
                return (flag_prio, 0, num)
            except ValueError:
                return (flag_prio, 1, x.payload)

        return sorted(results, key=sort_key)

    @staticmethod
    def to_curl(method: str, url: str, headers: Dict[str, str], body: str) -> str:
        parts = [f"curl -i -X {method.upper()} '{url}'"]
        for k, v in headers.items():
            parts.append(f"-H '{k}: {v}'")
        if body:
            escaped_body = body.replace("'", "'\\''")
            parts.append(f"--data-raw '{escaped_body}'")
        return " \\\n  ".join(parts)

    @staticmethod
    def to_python_requests(method: str, url: str, headers: Dict[str, str], body: str) -> str:
        code = [
            "import requests",
            "",
            f"url = {repr(url)}",
            f"headers = {repr(headers)}",
        ]
        if body:
            code.append(f"data = {repr(body)}")
            code.append(f"response = requests.{method.lower()}(url, headers=headers, data=data, verify=False)")
        else:
            code.append(f"response = requests.{method.lower()}(url, headers=headers, verify=False)")
        code.append("print('Status:', response.status_code)")
        code.append("print('Response:\\n', response.text)")
        return "\n".join(code)

    @staticmethod
    def diff_responses(resp_a: str, resp_b: str, label_a: str = "Resp A", label_b: str = "Resp B") -> str:
        lines_a = resp_a.splitlines(keepends=True)
        lines_b = resp_b.splitlines(keepends=True)
        diff = difflib.unified_diff(lines_a, lines_b, fromfile=label_a, tofile=label_b)
        return "".join(diff) or "[+] Both responses are identical!"
