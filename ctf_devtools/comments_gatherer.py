from __future__ import annotations
"""Unified Comments Gatherer for HTML, inline styles/scripts, and external CSS/JS files."""
import asyncio
import re
import urllib.parse
from typing import List, Dict, Any, Optional
import httpx
from bs4 import BeautifulSoup, Comment

from .flags import FlagTracker

SUSPICIOUS_REGEX = re.compile(
    r'(flag|ctf|picoctf|htb|todo|admin|debug|secret|pass|key|hidden|token|auth|part\s*\d|\d\s*/\s*\d)',
    re.I
)

class CommentsGatherer:
    """Recursively extracts and groups comments across HTML, CSS, and JS assets."""

    def __init__(self, base_url: str, flag_tracker: Optional[FlagTracker] = None):
        self.base_url = base_url
        self.flag_tracker = flag_tracker or FlagTracker()
        self.comments: List[Dict[str, Any]] = []

    def extract_from_code(self, code: str, file_type: str) -> List[str]:
        """Extracts C-style block comments and line comments from code."""
        results = []
        # Block comments: /* ... */
        for match in re.finditer(r'/\*([\s\S]*?)\*/', code):
            text = match.group(1).strip()
            if text:
                results.append(f'/* {text} */')
        # Line comments for JS / TS: // ...
        if file_type.lower() in ('js', 'javascript', 'ts', 'jsx', 'jsonc'):
            for match in re.finditer(r'//(.*)$', code, re.MULTILINE):
                text = match.group(1).strip()
                if text:
                    results.append(f'// {text}')
        return results

    async def gather_all(self, html: str) -> List[Dict[str, Any]]:
        """Gathers all comments from HTML and all linked CSS/JS files."""
        self.comments = []
        soup = BeautifulSoup(html, 'html.parser')

        # 1. HTML comments <!-- ... -->
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(c).strip()
            if not text:
                continue
            formatted = f'<!-- {text} -->'
            is_susp = bool(SUSPICIOUS_REGEX.search(text))
            self.comments.append({
                'origin': self.base_url,
                'file_type': 'HTML',
                'comment': formatted,
                'suspicious': is_susp
            })
            if is_susp and self.flag_tracker:
                self.flag_tracker.scan(text)

        # 2. Inline <style> blocks
        for style in soup.find_all('style'):
            content = style.string or ''
            if content.strip():
                for comm in self.extract_from_code(content, 'css'):
                    is_susp = bool(SUSPICIOUS_REGEX.search(comm))
                    self.comments.append({
                        'origin': f'{self.base_url} [inline <style>]',
                        'file_type': 'Inline CSS',
                        'comment': comm,
                        'suspicious': is_susp
                    })
                    if is_susp and self.flag_tracker:
                        self.flag_tracker.scan(comm)

        # 3. Inline <script> blocks
        for script in soup.find_all('script'):
            if not script.get('src'):
                content = script.string or ''
                if content.strip():
                    for comm in self.extract_from_code(content, 'js'):
                        is_susp = bool(SUSPICIOUS_REGEX.search(comm))
                        self.comments.append({
                            'origin': f'{self.base_url} [inline <script>]',
                            'file_type': 'Inline JS',
                            'comment': comm,
                            'suspicious': is_susp
                        })
                        if is_susp and self.flag_tracker:
                            self.flag_tracker.scan(comm)

        # 4. Find all external CSS and JS files
        external_assets = []
        for link in soup.find_all('link', href=True):
            href = link['href'].strip()
            rel = ' '.join(link.get('rel', [])).lower()
            if 'stylesheet' in rel or href.endswith('.css'):
                full_url = urllib.parse.urljoin(self.base_url, href)
                external_assets.append((full_url, 'CSS'))

        for script in soup.find_all('script', src=True):
            src = script['src'].strip()
            if src.endswith('.js'):
                full_url = urllib.parse.urljoin(self.base_url, src)
                external_assets.append((full_url, 'JS'))

        # Deduplicate assets
        seen_urls = set()
        unique_assets = []
        for url, kind in external_assets:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_assets.append((url, kind))

        # Fetch external assets concurrently
        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            tasks = [self._fetch_and_extract(client, url, kind) for url, kind in unique_assets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    self.comments.extend(res)

        return self.comments

    async def _fetch_and_extract(self, client: httpx.AsyncClient, url: str, kind: str) -> List[Dict[str, Any]]:
        extracted = []
        try:
            r = await client.get(url)
            if r.status_code == 200 and len(r.content) < 500_000:
                comments = self.extract_from_code(r.text, kind)
                for comm in comments:
                    is_susp = bool(SUSPICIOUS_REGEX.search(comm))
                    extracted.append({
                        'origin': url,
                        'file_type': kind,
                        'comment': comm,
                        'suspicious': is_susp
                    })
                    if is_susp and self.flag_tracker:
                        self.flag_tracker.scan(comm)
        except Exception:
            pass
        return extracted

    def format_report(self) -> str:
        """Formats a grouped readable report for display in the TUI."""
        if not self.comments:
            return 'No comments discovered across HTML or linked assets.'

        suspicious_count = sum(1 for c in self.comments if c['suspicious'])
        lines = [
            f"=== GATHERED COMMENTS REPORT ({len(self.comments)} total, {suspicious_count} suspicious) ===\n"
        ]

        # Group by origin
        by_origin: Dict[str, List[Dict[str, Any]]] = {}
        for c in self.comments:
            by_origin.setdefault(c['origin'], []).append(c)

        for origin, group in by_origin.items():
            first = group[0]
            kind = first['file_type']
            lines.append(f"┌─ [{kind}] {origin} ({len(group)} comments)")
            for item in group:
                badge = "[!] FLAG/SECRET CANDIDATE: " if item['suspicious'] else "• "
                comment_lines = item['comment'].splitlines()
                lines.append(f"│  {badge}{comment_lines[0]}")
                for cl in comment_lines[1:]:
                    lines.append(f"│    {cl}")
            lines.append("└" + "─" * 60 + "\n")

        return "\n".join(lines)
