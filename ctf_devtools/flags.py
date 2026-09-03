from __future__ import annotations
"""Flag detection and pattern tracking."""
import re
from typing import List, Set

DEFAULT_PATTERNS = [
    r"[a-zA-Z0-9_-]+CTF\{[^\s\"'<>]+\}",
    r"flag\{[^\s\"'<>]+\}",
    r"FLAG\{[^\s\"'<>]+\}",
    r"ctf\{[^\s\"'<>]+\}",
    r"CTF\{[^\s\"'<>]+\}",
    r"picoCTF\{[^\s\"'<>]+\}",
    r"HTB\{[^\s\"'<>]+\}",
    r"THM\{[^\s\"'<>]+\}",
]

class FlagTracker:
    def __init__(self, custom_regex: str = None):
        self.patterns = list(DEFAULT_PATTERNS)
        if custom_regex:
            self.patterns.insert(0, custom_regex)
        self.compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]
        self.found_flags: Set[str] = set()

    def scan(self, text: str, source: str = "") -> List[str]:
        if not text:
            return []
        new_matches = []
        for pat in self.compiled:
            for match in pat.findall(text):
                cleaned = match.strip()
                if cleaned not in self.found_flags:
                    self.found_flags.add(cleaned)
                    new_matches.append(cleaned)
        return new_matches

    def get_all_flags(self) -> List[str]:
        return sorted(list(self.found_flags))
