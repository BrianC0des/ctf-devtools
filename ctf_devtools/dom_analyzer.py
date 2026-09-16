from __future__ import annotations
"""DOM, HTML comments, forms, and asset/file extraction."""
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import httpx
from bs4 import BeautifulSoup, Comment

@dataclass
class DOMResponse:
    body: str
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)

class CommentItem(str):
    def __new__(cls, text: str, suspicious: bool = False):
        obj = super().__new__(cls, text)
        obj.suspicious = suspicious
        return obj

    def __getitem__(self, key):
        if key == "comment":
            return str(self)
        if key == "suspicious":
            return self.suspicious
        return super().__getitem__(key)

class DOMAnalyzer:
    def __init__(
        self,
        target_or_html: str,
        flag_tracker: Optional[Any] = None,
        cookie_storage: Optional[Any] = None,
        base_url: str = ""
    ):
        # Support legacy / test_suite signature: DOMAnalyzer(html_content, base_url="")
        if isinstance(flag_tracker, str):
            base_url = flag_tracker
            flag_tracker = None

        self.flag_tracker = flag_tracker
        self.cookie_storage = cookie_storage
        self.url = ""
        self.base_url = base_url
        self.html = ""

        # Determine whether target_or_html is raw HTML or a URL
        is_html = (
            "<" in target_or_html
            or "\n" in target_or_html
            or target_or_html.strip().startswith("<!DOCTYPE")
        )

        if is_html:
            self.html = target_or_html
            self.base_url = base_url
            self.soup = BeautifulSoup(self.html, "html.parser")
        else:
            raw_url = target_or_html.strip()
            if raw_url and not (raw_url.startswith("http://") or raw_url.startswith("https://")):
                raw_url = f"http://{raw_url}"
            self.url = raw_url
            self.base_url = base_url or self.url
            self.soup = BeautifulSoup("", "html.parser")

    async def fetch_and_parse(self, timeout: float = 10.0) -> DOMResponse:
        """Fetches the target URL asynchronously and parses DOM elements, forms, and comments."""
        if not self.url:
            if not self.soup or not self.soup.contents:
                self.soup = BeautifulSoup(self.html, "html.parser")
            return DOMResponse(body=self.html, status_code=200, headers={})

        headers: Dict[str, str] = {}
        if self.cookie_storage and hasattr(self.cookie_storage, "get_merged_headers"):
            headers = self.cookie_storage.get_merged_headers()
        headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CTF-DevTools/1.0")

        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            r = await client.get(self.url, headers=headers)
            self.html = r.text
            self.soup = BeautifulSoup(self.html, "html.parser")
            self.base_url = str(r.url)

            # Store cookies if cookie_storage present
            if self.cookie_storage and hasattr(self.cookie_storage, "parse_set_cookie"):
                for h in getattr(r, "history", []):
                    for sc in h.headers.get_list("set-cookie"):
                        self.cookie_storage.parse_set_cookie(sc)
                for sc in r.headers.get_list("set-cookie"):
                    self.cookie_storage.parse_set_cookie(sc)

            # Scan flags if flag_tracker present
            if self.flag_tracker and hasattr(self.flag_tracker, "scan"):
                self.flag_tracker.scan(self.html)

            return DOMResponse(
                body=self.html,
                status_code=r.status_code,
                headers=dict(r.headers)
            )

    @property
    def comments(self) -> List[CommentItem]:
        raw = self.extract_comments()
        return [CommentItem(c["comment"], c.get("suspicious", False)) for c in raw]

    @property
    def forms(self) -> List[Dict[str, Any]]:
        return self.extract_forms()

    @property
    def parameters(self) -> List[Dict[str, Any]]:
        return self.extract_parameters()

    def extract_comments(self) -> List[Dict[str, Any]]:
        comments = []
        for c in self.soup.find_all(string=lambda text: isinstance(text, Comment)):
            text = str(c).strip()
            if not text:
                continue
            is_suspicious = bool(re.search(r'(flag|ctf|todo|admin|debug|secret|pass|key|hidden)', text, re.I))
            comments.append({
                "comment": text,
                "suspicious": is_suspicious
            })
        return comments

    def extract_forms(self) -> List[Dict[str, Any]]:
        forms = []
        for form in self.soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                inp_type = inp.get("type", "text")
                value = inp.get("value", "")
                is_hidden = (inp_type == "hidden") or inp.has_attr("hidden")
                is_disabled = inp.has_attr("disabled")
                inputs.append({
                    "name": name,
                    "type": inp_type,
                    "value": value,
                    "hidden": is_hidden,
                    "disabled": is_disabled
                })
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })
        return forms

    def extract_parameters(self) -> List[Dict[str, Any]]:
        """Extracts URL query parameters and HTML form fields into a unified list."""
        parameters = []
        
        # 1. URL Query Parameters
        if self.base_url and "?" in self.base_url:
            parsed = urllib.parse.urlparse(self.base_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for key, values in qs.items():
                for val in values:
                    parameters.append({
                        "source": "URL Query",
                        "method": "GET",
                        "name": key,
                        "type": "query",
                        "value": val,
                        "target_url": self.base_url,
                        "form_all_inputs": []
                    })

        # 2. Form Inputs
        for form in self.extract_forms():
            action_url = urllib.parse.urljoin(self.base_url, form["action"]) if self.base_url else (form["action"] or "/")
            for inp in form["inputs"]:
                if inp["name"]:
                    parameters.append({
                        "source": f"Form ({form['action'] or '/'})",
                        "method": form["method"],
                        "name": inp["name"],
                        "type": inp["type"],
                        "value": inp["value"],
                        "target_url": action_url,
                        "form_all_inputs": form["inputs"]
                    })
        return parameters

    def extract_assets(self) -> List[Dict[str, str]]:
        assets = []
        seen = set()

        def add_asset(raw_url: str, kind: str):
            if not raw_url or raw_url.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                return
            full_url = urllib.parse.urljoin(self.base_url, raw_url) if self.base_url else raw_url
            if full_url in seen:
                return
            seen.add(full_url)
            
            map_url = None
            if full_url.endswith('.js') or full_url.endswith('.css'):
                map_url = f"{full_url}.map"

            assets.append({
                "url": full_url,
                "path": raw_url,
                "type": kind,
                "map_url": map_url
            })

        # Scripts
        for s in self.soup.find_all("script", src=True):
            add_asset(s["src"].strip(), "JavaScript")

        # Stylesheets & links
        for link in self.soup.find_all("link", href=True):
            rel = " ".join(link.get("rel", [])).lower()
            href = link["href"].strip()
            if "stylesheet" in rel or href.endswith('.css'):
                add_asset(href, "CSS")
            elif "icon" in rel:
                add_asset(href, "Icon")
            elif "manifest" in rel or href.endswith('.json'):
                add_asset(href, "Manifest/JSON")
            else:
                add_asset(href, "Link/Asset")

        # Images & media
        for img in self.soup.find_all("img", src=True):
            add_asset(img["src"].strip(), "Image")
        for source in self.soup.find_all("source", src=True):
            add_asset(source["src"].strip(), "Media")

        # Anchors pointing to downloadable files
        file_exts = ('.json', '.xml', '.txt', '.pdf', '.zip', '.tar.gz', '.wasm', '.bak', '.sql', '.conf')
        for a in self.soup.find_all("a", href=True):
            href = a["href"].strip()
            if any(href.lower().split('?')[0].endswith(ext) for ext in file_exts):
                add_asset(href, "Document/Data")

        return assets

    def extract_scripts(self) -> List[Dict[str, str]]:
        scripts = []
        for s in self.soup.find_all("script"):
            src = s.get("src")
            if src:
                has_map_candidate = src.endswith('.js')
                scripts.append({
                    "type": "external",
                    "src": src,
                    "map_url": f"{src}.map" if has_map_candidate else None
                })
            else:
                inline = s.string or ""
                if inline.strip():
                    scripts.append({
                        "type": "inline",
                        "content": inline[:200] + ("..." if len(inline) > 200 else "")
                    })
        return scripts

    def extract_links(self) -> List[str]:
        links = set()
        for a in self.soup.find_all("a", href=True):
            href = a["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                links.add(href)
        return sorted(list(links))
