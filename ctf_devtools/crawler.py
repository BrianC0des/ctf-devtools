"""Site spider and JavaScript endpoint extractor."""
import asyncio
import re
import urllib.parse
from dataclasses import dataclass
from typing import Set, Dict, List, Optional, Any
import httpx
from bs4 import BeautifulSoup
from .flags import FlagTracker

ENDPOINT_REGEX = re.compile(r"""(?:"|')((?:/[a-zA-Z0-9_\-\.\?&=#%]+)+)(?:"|')""")

@dataclass
class DiscoveredEndpoint:
    url: str
    status: int
    source: str
    content_type: str

class CTFCrawler:
    def __init__(self, start_url: str, flag_tracker: Optional[FlagTracker] = None, max_depth: int = 2, max_pages: int = 40):
        self.start_url = start_url.rstrip('/')
        self.parsed_start = urllib.parse.urlparse(self.start_url)
        self.flag_tracker = flag_tracker or FlagTracker()
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.discovered: Dict[str, DiscoveredEndpoint] = {}
        self.js_endpoints: Set[str] = set()

    def is_same_host(self, url: str) -> bool:
        p = urllib.parse.urlparse(url)
        return p.netloc == self.parsed_start.netloc or not p.netloc

    async def crawl(self) -> Dict[str, Any]:
        queue = [(self.start_url, 0)]
        limits = httpx.Limits(max_connections=8)
        
        async with httpx.AsyncClient(limits=limits, timeout=8.0, verify=False) as client:
            while queue and len(self.visited) < self.max_pages:
                current_url, depth = queue.pop(0)
                if current_url in self.visited or depth > self.max_depth:
                    continue

                self.visited.add(current_url)
                try:
                    r = await client.get(current_url, follow_redirects=True)
                    content_type = r.headers.get("content-type", "")
                    self.discovered[current_url] = DiscoveredEndpoint(
                        url=current_url,
                        status=r.status_code,
                        source="crawler",
                        content_type=content_type
                    )
                    self.flag_tracker.scan(r.text)

                    # Extract endpoints from JS files
                    if "javascript" in content_type or current_url.endswith(".js"):
                        for match in ENDPOINT_REGEX.findall(r.text):
                            if match.startswith('/') and not match.startswith('//'):
                                full = urllib.parse.urljoin(self.start_url, match)
                                self.js_endpoints.add(full)
                        continue

                    # Extract HTML links
                    if "text/html" in content_type:
                        soup = BeautifulSoup(r.text, "html.parser")
                        for tag, attr in [("a", "href"), ("script", "src"), ("form", "action"), ("iframe", "src")]:
                            for el in soup.find_all(tag, **{attr: True}):
                                link = el[attr].strip()
                                if link and not link.startswith(("#", "javascript:", "mailto:")):
                                    full_url = urllib.parse.urljoin(current_url, link)
                                    clean_url = full_url.split('#')[0]
                                    if self.is_same_host(clean_url) and clean_url not in self.visited:
                                        queue.append((clean_url, depth + 1))
                                    elif not self.is_same_host(clean_url):
                                        self.discovered[clean_url] = DiscoveredEndpoint(
                                            url=clean_url,
                                            status=0,
                                            source="external link",
                                            content_type=""
                                        )
                except Exception:
                    pass

        return {
            "visited_count": len(self.visited),
            "discovered": list(self.discovered.values()),
            "js_endpoints": sorted(list(self.js_endpoints))
        }
