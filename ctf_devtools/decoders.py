from __future__ import annotations
"""Encoding, decoding, hash identification, and session token analysis."""
import base64
import codecs
import html
import json
import re
import urllib.parse
import zlib
from typing import Dict, Any, List, Optional, Tuple, Union

def base64_decode(text: str) -> str:
    text = text.strip()
    padding = '=' * (-len(text) % 4)
    try:
        raw = base64.b64decode(text + padding)
        return raw.decode('utf-8', errors='replace')
    except Exception:
        try:
            raw = base64.urlsafe_b64decode(text + padding)
            return raw.decode('utf-8', errors='replace')
        except Exception as e:
            return f"[Base64 decode error: {e}]"

def base64_encode(text: str) -> str:
    try:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    except Exception as e:
        return f"[Base64 encode error: {e}]"

def hex_decode(text: str) -> str:
    clean = re.sub(r'[^0-9a-fA-F]', '', text)
    if not clean:
        return "[Hex decode error: No valid hex digits found]"
    if len(clean) % 2 != 0:
        clean = '0' + clean
    try:
        return bytes.fromhex(clean).decode('utf-8', errors='replace')
    except Exception as e:
        return f"[Hex decode error: {e}]"

def hex_encode(text: str) -> str:
    try:
        return text.encode('utf-8').hex()
    except Exception as e:
        return f"[Hex encode error: {e}]"

def url_decode(text: str) -> str:
    try:
        first = urllib.parse.unquote(text)
        second = urllib.parse.unquote(first)
        if first != second:
            return f"[Double Decoded]: {second}\n[Single Decoded]: {first}"
        return first
    except Exception as e:
        return f"[URL decode error: {e}]"

def url_encode(text: str) -> str:
    try:
        return urllib.parse.quote(text, safe='')
    except Exception as e:
        return f"[URL encode error: {e}]"

def html_decode(text: str) -> str:
    try:
        return html.unescape(text)
    except Exception as e:
        return f"[HTML decode error: {e}]"

def html_encode(text: str) -> str:
    try:
        return html.escape(text)
    except Exception as e:
        return f"[HTML encode error: {e}]"

def rot13(text: str) -> str:
    try:
        return codecs.encode(text, 'rot_13')
    except Exception as e:
        return f"[ROT13 error: {e}]"

def inspect_jwt(token: str) -> Dict[str, Any]:
    token = token.strip()
    parts = token.split('.')
    if len(parts) < 2:
        return {"error": f"Invalid JWT format: expected at least 2 parts, got {len(parts)}"}

    def _b64_url_decode(s: str) -> str:
        s += '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s).decode('utf-8', errors='replace')

    try:
        header_str = _b64_url_decode(parts[0])
        payload_str = _b64_url_decode(parts[1])
        header = json.loads(header_str)
        payload = json.loads(payload_str)
    except Exception as e:
        return {"error": f"Failed to decode JWT parts: {e}"}

    analysis = []
    alg = header.get("alg", "")
    if str(alg).lower() == "none":
        analysis.append("[!] INSECURE: Algorithm is 'none' (unsigned token)!")
    if "exp" in payload:
        analysis.append(f"Expiration (exp): {payload['exp']}")

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2] if len(parts) > 2 else "",
        "analysis": analysis
    }

def unpack_flask_session(cookie: str) -> Dict[str, Any]:
    cookie = cookie.strip()
    raw = cookie
    if raw.startswith('.'):
        raw = raw[1:]
    parts = raw.split('.')
    if not parts:
        return {"error": "Invalid session string"}
    
    payload_part = parts[0]
    padding = '=' * (-len(payload_part) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_part + padding)
        try:
            decompressed = zlib.decompress(decoded)
            return {"type": "Flask/Werkzeug (zlib compressed)", "data": json.loads(decompressed.decode('utf-8', errors='replace'))}
        except Exception:
            return {"type": "Flask/Werkzeug (uncompressed)", "data": json.loads(decoded.decode('utf-8', errors='replace'))}
    except Exception as e:
        return {"error": f"Could not unpack Flask session: {e}"}

COMMON_FLASK_SECRETS = [
    # picoCTF Most Cookies list
    "snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", 
    "peanut butter", "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", 
    "spritz", "snowball", "drop", "thumbprint", "pinwheel", "wafer", "macaroon", 
    "fortune", "crinkle", "icebox", "gingerbread", "tassie", "lebkuchen", "macaron", 
    "black and white", "white chocolate macadamia",
    # General CTF common secrets
    "secret", "secret_key", "dev", "development", "admin", "password", "123456",
    "flask", "changeme", "test", "supersecret", "secretkey", "key", "root"
]

def crack_flask_session(cookie: str, custom_words: Optional[List[str]] = None) -> Optional[str]:
    """Attempts to find the signing secret_key for a Flask session cookie using common keys."""
    try:
        import hashlib
        from itsdangerous import URLSafeTimedSerializer
        from flask.sessions import TaggedJSONSerializer
    except ImportError:
        return None

    wordlist = list(custom_words or []) + COMMON_FLASK_SECRETS
    seen = set()
    words = [w for w in wordlist if not (w in seen or seen.add(w))]

    for secret in words:
        try:
            s = URLSafeTimedSerializer(
                secret_key=secret,
                salt="cookie-session",
                serializer=TaggedJSONSerializer(),
                signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1}
            )
            s.loads(cookie)
            return secret
        except Exception:
            continue
    return None

def sign_flask_session(data: dict, secret_key: str) -> str:
    """Signs a dict payload into a valid Flask session cookie using the given secret_key."""
    import hashlib
    from itsdangerous import URLSafeTimedSerializer
    from flask.sessions import TaggedJSONSerializer

    s = URLSafeTimedSerializer(
        secret_key=secret_key,
        salt="cookie-session",
        serializer=TaggedJSONSerializer(),
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1}
    )
    return s.dumps(data)

def identify_hash(h: str) -> List[str]:
    h = h.strip()
    matches = []
    if re.fullmatch(r'[a-fA-F0-9]{32}', h):
        matches.extend(["MD5", "NTLM", "MD4"])
    if re.fullmatch(r'[a-fA-F0-9]{40}', h):
        matches.extend(["SHA-1", "MySQL5"])
    if re.fullmatch(r'[a-fA-F0-9]{56}', h):
        matches.extend(["SHA-224"])
    if re.fullmatch(r'[a-fA-F0-9]{64}', h):
        matches.extend(["SHA-256"])
    if re.fullmatch(r'[a-fA-F0-9]{96}', h):
        matches.extend(["SHA-384"])
    if re.fullmatch(r'[a-fA-F0-9]{128}', h):
        matches.extend(["SHA-512"])
    if h.startswith('$2a$') or h.startswith('$2b$') or h.startswith('$2y$'):
        matches.append("bcrypt")
    if h.startswith('$6$'):
        matches.append("SHA-512 crypt (Linux)")
    if h.startswith('$5$'):
        matches.append("SHA-256 crypt (Linux)")
    if h.startswith('$1$'):
        matches.append("MD5 crypt (Linux)")
    return matches or ["Unknown or custom hash format"]
