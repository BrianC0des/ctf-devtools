from __future__ import annotations
"""Storage and Cookie Manager: Cookie Jar, Global Auth Headers, and Client Storage Harvester."""
import json
import re
from http.cookies import SimpleCookie
from typing import Dict, List, Any, Optional

from .decoders import (
    inspect_jwt, unpack_flask_session, base64_decode,
    crack_flask_session, sign_flask_session
)

class CookieAndStorageManager:
    """Manages active cookies, global authentication headers, and client-side storage tokens."""

    def __init__(self):
        self.cookies: Dict[str, Dict[str, Any]] = {}
        self.global_headers: Dict[str, str] = {}
        self.harvested_storage: List[Dict[str, str]] = []

    def parse_set_cookie(self, set_cookie_header: str) -> List[Dict[str, Any]]:
        """Parses a Set-Cookie response header into the active jar."""
        if not set_cookie_header:
            return []
        added = []
        cookie = SimpleCookie()
        try:
            cookie.load(set_cookie_header)
            for key, morsel in cookie.items():
                entry = {
                    "name": key,
                    "value": morsel.value,
                    "path": morsel.get("path", "/"),
                    "httponly": bool(morsel.get("httponly", False)),
                    "secure": bool(morsel.get("secure", False)),
                }
                self.cookies[key] = entry
                added.append(entry)
        except Exception:
            # Fallback simple split if SimpleCookie fails on non-standard formats
            for part in set_cookie_header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if k.lower() not in ("path", "domain", "expires", "samesite", "max-age"):
                        entry = {
                            "name": k,
                            "value": v,
                            "path": "/",
                            "httponly": False,
                            "secure": False,
                        }
                        self.cookies[k] = entry
                        added.append(entry)
                        break
        return added

    def set_cookie(self, name: str, value: str, path: str = "/", httponly: bool = False, secure: bool = False):
        """Manually sets or updates a cookie."""
        self.cookies[name] = {
            "name": name,
            "value": value,
            "path": path,
            "httponly": httponly,
            "secure": secure,
        }

    def delete_cookie(self, name: str):
        """Removes a cookie from the jar."""
        if name in self.cookies:
            del self.cookies[name]

    def get_cookie_header(self) -> str:
        """Returns standard Cookie: name=value; name2=value2 string."""
        if not self.cookies:
            return ""
        return "; ".join([f"{k}={v['value']}" for k, v in self.cookies.items()])

    def set_global_header(self, name: str, value: str):
        """Sets a global header (e.g. Authorization or X-Forwarded-For)."""
        self.global_headers[name.strip()] = value.strip()

    def remove_global_header(self, name: str):
        """Removes a global header."""
        if name.strip() in self.global_headers:
            del self.global_headers[name.strip()]

    def get_merged_headers(self, existing_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Merges global headers and Cookie header into request headers."""
        merged = dict(existing_headers or {})
        for k, v in self.global_headers.items():
            if k not in merged:
                merged[k] = v
        
        cookie_hdr = self.get_cookie_header()
        if cookie_hdr:
            has_cookie = any(k.lower() == "cookie" for k in merged)
            if not has_cookie:
                merged["Cookie"] = cookie_hdr
        return merged

    def decode_cookie_value(self, value: str) -> str:
        """Attempts to intelligently decode a cookie value (JWT, Flask, Base64)."""
        clean = value.strip()
        # 1. Test JWT
        jwt_res = inspect_jwt(clean)
        if jwt_res.get("valid_jwt"):
            return f"[JWT Detected]\n{json.dumps(jwt_res, indent=2)}"

        # 2. Test Flask / Werkzeug Session
        flask_res = unpack_flask_session(clean)
        if "error" not in flask_res:
            res_str = f"[Flask / Werkzeug Session Detected]\n{json.dumps(flask_res, indent=2)}"
            cracked_secret = crack_flask_session(clean)
            if cracked_secret:
                payload_data = flask_res.get("data", {})
                forged_admin = dict(payload_data) if isinstance(payload_data, dict) else {}
                if "very_auth" in forged_admin:
                    forged_admin["very_auth"] = "admin"
                else:
                    forged_admin["admin"] = True
                
                try:
                    forged_cookie = sign_flask_session(forged_admin, cracked_secret)
                    res_str += f"\n\n[+] CRACKED SECRET KEY: '{cracked_secret}'"
                    res_str += f"\n[+] FORGED ADMIN COOKIE:\n{forged_cookie}"
                    res_str += f"\n\n[💡 TIP] Paste this forged cookie into the Value box above or into Repeater to access admin/flag pages!"
                except Exception:
                    res_str += f"\n\n[+] CRACKED SECRET KEY: '{cracked_secret}'"
            return res_str

        # 3. Test Base64
        try:
            b64_res = base64_decode(clean)
            if b64_res and not b64_res.startswith("[Error]") and any(c.isalnum() for c in b64_res):
                return f"[Base64 Decoded]\n{b64_res}"
        except Exception:
            pass

        return f"[Raw Cookie Value]\n{value}"

    def harvest_storage_from_code(self, code: str, source_url: str = "") -> List[Dict[str, str]]:
        """Scans JavaScript code for localStorage, sessionStorage, and document.cookie patterns."""
        results = []
        seen = set()

        patterns = [
            ("localStorage.setItem", r"localStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)"),
            ("sessionStorage.setItem", r"sessionStorage\.setItem\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)"),
            ("document.cookie", r"document\.cookie\s*=\s*['\"]([^'\"]+)['\"]"),
            ("localStorage[key]", r"localStorage\[['\"]([^'\"]+)['\"]\]\s*=\s*['\"]([^'\"]*)['\"]"),
            ("sessionStorage[key]", r"sessionStorage\[['\"]([^'\"]+)['\"]\]\s*=\s*['\"]([^'\"]*)['\"]"),
        ]

        for p_name, pat in patterns:
            for m in re.finditer(pat, code):
                groups = m.groups()
                key = groups[0]
                val = groups[1] if len(groups) > 1 else ""
                ident = (p_name, key, val)
                if ident not in seen:
                    seen.add(ident)
                    results.append({
                        "api": p_name,
                        "key": key,
                        "value": val,
                        "source": source_url or "inline/code"
                    })

        self.harvested_storage.extend(results)
        return results
