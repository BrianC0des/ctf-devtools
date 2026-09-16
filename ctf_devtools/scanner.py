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

    @property
    def body_snippet(self) -> str:
        return self.snippet or (self.body[:150].replace('\n', ' ').strip() if self.body else "")

def detect_templates_and_frameworks(
    headers: Dict[str, str],
    cookies: Optional[Dict[str, Any]] = None,
    html_body: str = ""
) -> Dict[str, str]:
    """Passively detects web frameworks and template engines based on HTTP headers, cookies, and DOM markers."""
    findings: Dict[str, str] = {}
    hdrs_lower = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    cookie_keys = set()
    if cookies:
        cookie_keys = {str(k).lower() for k in cookies.keys()}
        for k, v in cookies.items():
            if isinstance(v, dict) and "name" in v:
                cookie_keys.add(str(v["name"]).lower())

    server = hdrs_lower.get("server", "")
    powered = hdrs_lower.get("x-powered-by", "")

    # Python / Flask / Jinja2
    if "werkzeug" in server or "flask" in powered or ("session" in cookie_keys and any(".eJ" in str(v) for v in (cookies.values() if cookies else []))):
        findings["Framework"] = "Flask (Python)"
        findings["Template Engine"] = "Jinja2"
    elif "django" in powered or "csrftoken" in cookie_keys or "sessionid" in cookie_keys:
        findings["Framework"] = "Django (Python)"
        findings["Template Engine"] = "Django Template Language (DTL)"
    elif "tornado" in server:
        findings["Framework"] = "Tornado (Python)"
        findings["Template Engine"] = "Tornado Templates"

    # PHP / Laravel / Twig / Blade
    if "php" in powered or "phpsessid" in cookie_keys or ".php" in server:
        if "laravel" in powered or "laravel_session" in cookie_keys or "xsrf-token" in hdrs_lower:
            findings["Framework"] = "Laravel (PHP)"
            findings["Template Engine"] = "Blade / Twig"
        elif "Framework" not in findings:
            findings["Framework"] = f"PHP ({powered or 'Standard'})"
            findings["Template Engine"] = "PHP / Twig / Smarty"

    # Node.js / Express / EJS
    if "express" in powered or "connect.sid" in cookie_keys:
        findings["Framework"] = "Express (Node.js)"
        findings["Template Engine"] = "EJS / Pug / Handlebars"

    # Java / Spring / Thymeleaf
    if "jsessionid" in cookie_keys or "spring" in powered or "tomcat" in server:
        findings["Framework"] = "Spring Boot / Java"
        findings["Template Engine"] = "Thymeleaf / JSP / Freemarker"

    # Ruby on Rails / ERB
    if "_rails_session" in cookie_keys or "phusion passenger" in server:
        findings["Framework"] = "Ruby on Rails"
        findings["Template Engine"] = "ERB / Slim"

    # ASP.NET / Razor
    if "asp.net" in powered or "iis" in server or "asp.net_sessionid" in cookie_keys:
        findings["Framework"] = "ASP.NET / C#"
        findings["Template Engine"] = "Razor"

    return findings

class CTFScanner:
    def __init__(self, base_url: str, flag_tracker: Optional[FlagTracker] = None, timeout: float = 6.0, cookie_storage: Optional[Any] = None):
        self.base_url = base_url.rstrip('/')
        self.flag_tracker = flag_tracker or FlagTracker()
        self.timeout = timeout
        self.cookie_storage = cookie_storage
        self.results: List[ScanResult] = []
        self.tech_stack: Dict[str, str] = {}
        self.framework_info: Dict[str, str] = {}
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

                # Passive template and framework fingerprinting
                cookies_dict = self.cookie_storage.cookies if self.cookie_storage else {}
                self.framework_info = detect_templates_and_frameworks(dict(base_resp.headers), cookies_dict, base_resp.text)
                for k, v in self.framework_info.items():
                    self.tech_stack[f"Detected {k}"] = v
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
