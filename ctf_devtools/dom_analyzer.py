"""DOM, HTML comments, forms, and asset/file extraction."""
import re
import urllib.parse
from typing import List, Dict, Any
from bs4 import BeautifulSoup, Comment

class DOMAnalyzer:
    def __init__(self, html_content: str, base_url: str = ""):
        self.html = html_content
        self.base_url = base_url
        self.soup = BeautifulSoup(html_content, "html.parser")

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
