"""Session persistence for CTF challenges."""
import json
import os
from typing import Dict, Any

class SessionManager:
    def __init__(self, challenge_name: str = "default_challenge"):
        self.challenge_name = challenge_name
        self.filename = f"{challenge_name}.ctf.json"

    def save(self, data: Dict[str, Any]) -> str:
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return os.path.abspath(self.filename)

    def load(self) -> Dict[str, Any]:
        if not os.path.exists(self.filename):
            return {}
        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
