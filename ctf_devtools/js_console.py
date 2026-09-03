"""JavaScript Interactive Console & Deobfuscation Engine for CTFs."""
import asyncio
import json
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

NODE_RUNNER_SCRIPT = r"""
const vm = require('vm');
const fs = require('fs');

try {
    const rawInput = fs.readFileSync(0, 'utf-8');
    const req = JSON.parse(rawInput);

    const storage = {};
    const sessionStorage = {};
    const logs = [];

    const customConsole = {
        log: (...args) => logs.push(args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' ')),
        info: (...args) => logs.push('[INFO] ' + args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' ')),
        warn: (...args) => logs.push('[WARN] ' + args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' ')),
        error: (...args) => logs.push('[ERR] ' + args.map(a => typeof a === 'object' ? JSON.stringify(a, null, 2) : String(a)).join(' ')),
        table: (data) => logs.push(typeof data === 'object' ? JSON.stringify(data, null, 2) : String(data)),
    };

    const sandbox = {
        console: customConsole,
        atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
        btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
        localStorage: {
            getItem: (k) => storage[k] !== undefined ? storage[k] : null,
            setItem: (k, v) => { storage[k] = String(v); },
            removeItem: (k) => { delete storage[k]; },
            clear: () => { for (let k in storage) delete storage[k]; }
        },
        sessionStorage: {
            getItem: (k) => sessionStorage[k] !== undefined ? sessionStorage[k] : null,
            setItem: (k, v) => { sessionStorage[k] = String(v); },
            removeItem: (k) => { delete sessionStorage[k]; },
            clear: () => { for (let k in sessionStorage) delete sessionStorage[k]; }
        },
        document: {
            cookie: req.cookies || '',
            title: 'CTF Challenge Sandbox',
            getElementById: () => null,
            querySelector: () => null,
            querySelectorAll: () => [],
        },
        location: {
            href: req.url || 'http://target.local/',
            origin: req.url ? new URL(req.url).origin : 'http://target.local',
            pathname: '/',
            search: '',
            hash: '',
        },
        setTimeout: (fn, ms) => {},
        clearTimeout: () => {},
        setInterval: () => {},
        clearInterval: () => {},
    };
    sandbox.window = sandbox;
    sandbox.global = sandbox;
    sandbox.globalThis = sandbox;
    sandbox.self = sandbox;

    vm.createContext(sandbox);

    if (req.preload && req.preload.trim().length > 0) {
        try {
            vm.runInContext(req.preload, sandbox, { timeout: 3000 });
        } catch (preloadErr) {
            logs.push('[WARN: Preloaded Script Warning]: ' + (preloadErr.message || preloadErr));
        }
    }

    let returnVal = undefined;
    let isError = false;
    let errorMsg = '';

    try {
        returnVal = vm.runInContext(req.code, sandbox, { timeout: 4000 });
    } catch (evalErr) {
        isError = true;
        errorMsg = evalErr.stack || evalErr.message || String(evalErr);
    }

    const output = {
        logs: logs,
        returnVal: returnVal !== undefined ? (typeof returnVal === 'object' ? JSON.stringify(returnVal, null, 2) : String(returnVal)) : null,
        isError: isError,
        errorMsg: errorMsg,
        cookie: sandbox.document.cookie,
    };

    process.stdout.write(JSON.stringify(output));
} catch (fatal) {
    process.stderr.write(fatal.stack || fatal.message || String(fatal));
}
"""

class JSConsoleEngine:
    """Runs an isolated JavaScript REPL and sandbox pre-loaded with CTF challenges and DOM mocks."""
    def __init__(self):
        self.node_bin = shutil.which("node") or shutil.which("bun") or shutil.which("deno")
        self.preloaded_scripts: List[str] = []
        self.preloaded_urls: List[str] = []

    def is_available(self) -> bool:
        return self.node_bin is not None

    def add_preloaded_script(self, url: str, code: str):
        if url not in self.preloaded_urls:
            self.preloaded_urls.append(url)
            self.preloaded_scripts.append(code)

    def clear_preloaded(self):
        self.preloaded_urls.clear()
        self.preloaded_scripts.clear()

    async def eval_js(self, code: str, url: str = "", cookies: str = "") -> Tuple[str, Optional[str], bool]:
        """
        Executes code inside the sandbox.
        Returns: (console_logs_str, return_val_str, is_error)
        """
        if not self.node_bin:
            return ("", "[!] Node.js or Bun is not installed on the system.", True)

        combined_preload = "\n;\n".join(self.preloaded_scripts)
        payload = {
            "code": code,
            "preload": combined_preload,
            "url": url,
            "cookies": cookies,
        }

        try:
            proc = await asyncio.create_subprocess_exec(
                self.node_bin, "-e", NODE_RUNNER_SCRIPT,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(input=json.dumps(payload).encode("utf-8"))
            
            if proc.returncode != 0 and stderr:
                return ("", f"[Execution Error]: {stderr.decode('utf-8', errors='ignore')}", True)

            try:
                res = json.loads(stdout.decode("utf-8", errors="ignore"))
                logs = "\n".join(res.get("logs", []))
                ret = res.get("returnVal")
                is_err = res.get("isError", False)
                err_msg = res.get("errorMsg", "")
                
                if is_err:
                    err_formatted = f"Runtime Error: {err_msg}"
                    return (logs, err_formatted, True)
                return (logs, ret, False)
            except Exception as parse_err:
                out_raw = stdout.decode('utf-8', errors='ignore')
                return (out_raw, None, False)

        except Exception as e:
            return ("", f"[Subprocess Exception]: {str(e)}", True)


def deobfuscate_javascript(code: str) -> str:
    """
    Deobfuscates hex/unicode escaping, string concatenations, and Dean Edwards packed scripts.
    """
    if not code:
        return ""
    
    # 1. Unpack Dean Edwards packer: eval(function(p,a,c,k,e,d)...)
    packer_match = re.search(r"eval\s*\(\s*(function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d.*?)\s*\)\s*;?", code, re.DOTALL)
    if packer_match:
        try:
            node = shutil.which("node")
            if node:
                runner = f"const fn = {packer_match.group(1)}; process.stdout.write(fn);"
                res = subprocess.run([node, "-e", runner], capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and res.stdout.strip():
                    unpacked = res.stdout.strip()
                    code = code[:packer_match.start()] + unpacked + code[packer_match.end():]
        except Exception:
            pass

    # 2. Decode hex escapes: \xHH
    def rep_hex(m):
        try:
            ch = chr(int(m.group(1), 16))
            if ch.isprintable() and ch not in ['"', "'", "\\"]:
                return ch
            elif ch in ['"', "'"]:
                return f"\\{ch}"
            return m.group(0)
        except Exception:
            return m.group(0)

    code = re.sub(r'\\x([0-9a-fA-F]{2})', rep_hex, code)

    # 3. Decode unicode escapes: \uHHHH
    def rep_uni(m):
        try:
            ch = chr(int(m.group(1), 16))
            if ch.isprintable() and ch not in ['"', "'", "\\"]:
                return ch
            return m.group(0)
        except Exception:
            return m.group(0)

    code = re.sub(r'\\u([0-9a-fA-F]{4})', rep_uni, code)

    # 4. Clean up string concatenations: 'a' + 'b' + 'c'
    code = re.sub(r"'([a-zA-Z0-9_-]+)'\s*\+\s*'([a-zA-Z0-9_-]+)'", r"'\1\2'", code)
    code = re.sub(r'"([a-zA-Z0-9_-]+)"\s*\+\s*"([a-zA-Z0-9_-]+)"', r'"\1\2"', code)

    return code


def generate_csrf_poc(method: str, url: str, fields: Dict[str, str]) -> str:
    """Generates a standalone auto-submitting HTML CSRF exploit PoC."""
    method = method.upper() if method else "POST"
    inputs_html = []
    for k, v in fields.items():
        inputs_html.append(f'      <input type="hidden" name="{k}" value="{v}" />')
    inputs_str = "\n".join(inputs_html) if inputs_html else '      <!-- No fields specified -->'

    return f"""<!DOCTYPE html>
<html>
  <head>
    <title>CTF CSRF Exploit PoC</title>
  </head>
  <body>
    <h3>CSRF PoC: {method} {url}</h3>
    <form id="csrf-form" action="{url}" method="{method}">
{inputs_str}
      <input type="submit" value="Submit Exploit" />
    </form>
    <script>
      // Auto-submit on victim interaction / load
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
"""
