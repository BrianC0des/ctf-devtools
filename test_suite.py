"""Comprehensive test runner for CTF DevTools modules."""
import asyncio
import http.server
import socketserver
import threading
import time
import httpx

from ctf_devtools.flags import FlagTracker
from ctf_devtools.decoders import (
    base64_decode, base64_encode, hex_decode, hex_encode,
    url_decode, url_encode, rot13, inspect_jwt,
    unpack_flask_session, identify_hash
)
from ctf_devtools.scanner import CTFScanner
from ctf_devtools.dom_analyzer import DOMAnalyzer
from ctf_devtools.crawler import CTFCrawler
from ctf_devtools.repeater import RepeaterEngine
from ctf_devtools.oob_listener import OOBListener

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 0))
PORT = s.getsockname()[1]
s.close()

HTML_DOC = """<!DOCTYPE html>
<html>
<head><title>CTF Target</title></head>
<body>
    <!-- TODO: remove CTF{dom_comment_flag_found} before deploy -->
    <form action="/login" method="POST">
        <input type="text" name="user" value="guest" />
        <input type="password" name="pass" />
        <input type="hidden" name="csrf" value="secret_csrf_123" />
        <input type="submit" value="Submit" disabled />
    </form>
    <a href="/about">About Us</a>
    <script src="/static/app.js"></script>
</body>
</html>"""

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path in ["/", "/index.html"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Werkzeug/3.0.1 Python/3.14")
            self.send_header("X-Powered-By", "Flask")
            self.end_headers()
            self.wfile.write(HTML_DOC.encode())
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin_panel\n")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASS=admin\nFLAG=CTF{env_file_leak_flag}\n")
        elif self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"const endpoint = '/api/v1/internal_metrics';")
        elif self.path == "/about":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>About Challenge</h1></body></html>")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

def start_server():
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", PORT), MockHandler)
    server.serve_forever()

async def run_tests():
    print("=== [1] TESTING DECODERS & TOKENS ===")
    assert base64_decode("Q1RGe2I2NF93b3Jrc30=") == "CTF{b64_works}"
    assert hex_decode("4354467b6865785f776f726b737d") == "CTF{hex_works}"
    assert rot13("PGS{ebg13_jbexf}") == "CTF{rot13_works}"
    jwt_res = inspect_jwt("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsImZsYWciOiJDVEZ7and0X29rfSJ9.")
    assert jwt_res["payload"]["flag"] == "CTF{jwt_ok}"
    assert any("INSECURE" in a for a in jwt_res["analysis"])
    hashes = identify_hash("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in hashes
    print("  ✓ Decoders, JWT Inspector, and Hash ID passed!")

    print("\n=== [2] TESTING DOM ANALYZER ===")
    dom = DOMAnalyzer(HTML_DOC)
    comments = dom.extract_comments()
    assert len(comments) == 1
    assert comments[0]["suspicious"] is True
    assert "CTF{dom_comment_flag_found}" in comments[0]["comment"]
    
    forms = dom.extract_forms()
    assert len(forms) == 1
    inputs = forms[0]["inputs"]
    hidden_inp = next(i for i in inputs if i["name"] == "csrf")
    assert hidden_inp["hidden"] is True
    assert hidden_inp["value"] == "secret_csrf_123"
    scripts = dom.extract_scripts()
    assert scripts[0]["src"] == "/static/app.js"
    assert scripts[0]["map_url"] == "/static/app.js.map"
    print("  ✓ DOM comments, forms, hidden inputs, and script extraction passed!")

    print("\n=== [3] TESTING RECON SCANNER ===")
    flags = FlagTracker()
    scanner = CTFScanner(f"http://127.0.0.1:{PORT}", flag_tracker=flags)
    results = await scanner.scan_all()
    paths = [r.path for r in results]
    assert "/robots.txt" in paths
    assert "/.env" in paths
    assert "server" in scanner.tech_stack
    assert "x-powered-by" in scanner.tech_stack
    assert any("CTF{env_file_leak_flag}" in r.flags for r in results)
    print("  ✓ CTF Recon scanner found /robots.txt, /.env, tech fingerprint, and auto-extracted flag!")

    print("\n=== [4] TESTING SITE CRAWLER & JS ENDPOINT SCRAPER ===")
    crawler = CTFCrawler(f"http://127.0.0.1:{PORT}", flag_tracker=flags)
    crawl_res = await crawler.crawl()
    assert len(crawl_res["discovered"]) >= 2
    assert any("/api/v1/internal_metrics" in ep for ep in crawl_res["js_endpoints"])
    print("  ✓ Crawler mapped pages and extracted JS endpoint /api/v1/internal_metrics!")

    print("\n=== [5] TESTING REPEATER & FUZZER ===")
    repeater = RepeaterEngine(flags)
    rep_res = await repeater.send_request("GET", f"http://127.0.0.1:{PORT}/.env", {})
    assert rep_res.status_code == 200
    assert "CTF{env_file_leak_flag}" in rep_res.body
    
    curl_str = repeater.to_curl("POST", f"http://127.0.0.1:{PORT}/login", {"Content-Type": "application/json"}, '{"user":"admin"}')
    assert "curl -i -X POST" in curl_str
    
    py_code = repeater.to_python_requests("POST", f"http://127.0.0.1:{PORT}/login", {}, "")
    assert "import requests" in py_code
    print("  ✓ Repeater replay, cURL export, and Python script generation passed!")

    print("\n=== [6] TESTING OOB CALLBACK LISTENER ===")
    oob_received = []
    listener = OOBListener(port=9998, on_hit=lambda req: oob_received.append(req))
    await listener.start()
    
    async with httpx.AsyncClient() as client:
        await client.post("http://127.0.0.1:9998/ssrf_flag_callback", content=b"CTF{oob_ssrf_worked}")
    
    await asyncio.sleep(0.1)
    await listener.stop()
    assert len(oob_received) == 1
    assert oob_received[0].path == "/ssrf_flag_callback"
    assert "CTF{oob_ssrf_worked}" in oob_received[0].body
    print("  ✓ Out-Of-Band callback listener caught blind SSRF payload!")

    print("\n=== [7] TESTING STORAGE & COOKIES MANAGER ===")
    from ctf_devtools.storage_mgr import CookieAndStorageManager
    csm = CookieAndStorageManager()
    csm.parse_set_cookie("session=admin_cookie_123; Path=/; HttpOnly")
    assert "session" in csm.cookies
    assert csm.cookies["session"]["value"] == "admin_cookie_123"
    assert csm.get_cookie_header() == "session=admin_cookie_123"

    csm.set_global_header("Authorization", "Bearer ctf_token")
    merged = csm.get_merged_headers({"User-Agent": "test"})
    assert merged["Authorization"] == "Bearer ctf_token"
    assert merged["Cookie"] == "session=admin_cookie_123"

    harvested = csm.harvest_storage_from_code(
        "localStorage.setItem('auth', 'CTF{storage_token}'); document.cookie = 'user=admin';",
        "bundle.js"
    )
    assert len(harvested) >= 2

    # Test Flask session auto-cracking and signing
    from ctf_devtools.decoders import crack_flask_session, sign_flask_session
    dummy_cookie = sign_flask_session({"very_auth": "blank"}, "butter")
    cracked = crack_flask_session(dummy_cookie)
    assert cracked == "butter"
    forged = sign_flask_session({"very_auth": "admin"}, cracked)
    assert crack_flask_session(forged) == "butter"
    decoded_view = csm.decode_cookie_value(dummy_cookie)
    assert "CRACKED SECRET KEY: 'butter'" in decoded_view

    print("  ✓ Cookie jar parsing, Flask session cracking/signing, and storage harvester passed!")

    print("\n=== [8] TESTING JS CONSOLE, SANDBOX & DEOBFUSCATOR ===")
    from ctf_devtools.js_console import JSConsoleEngine, deobfuscate_javascript, generate_csrf_poc
    js_engine = JSConsoleEngine()
    assert js_engine.is_available() is True
    
    # Execution in sandbox
    logs, ret, is_err = await js_engine.eval_js("console.log('Sandbox test'); 15 * 3;")
    assert "Sandbox test" in logs
    assert ret == "45"
    assert is_err is False

    # Preloaded script execution
    js_engine.add_preloaded_script("solve.js", "function solvePin(p) { return p === '1337' ? 'CTF{js_pin_solved}' : 'FAIL'; }")
    logs, ret, is_err = await js_engine.eval_js("solvePin('1337');")
    assert ret == "CTF{js_pin_solved}"
    flags.scan(ret)

    # Deobfuscator test
    obf_code = r'let secret = \x22\x70\x69\x63\x6f\x43\x54\x46\x7b\x75\x6e\x68\x65\x78\x7d\x22;'
    deobf = deobfuscate_javascript(obf_code)
    assert 'picoCTF{unhex}' in deobf
    print("  ✓ JS sandbox evaluation, target preloading, and hex/unicode deobfuscation passed!")

    print("\n=== [9] TESTING NETWORK TRAFFIC LOGGER & CSRF POC GENERATOR ===")
    from ctf_devtools.network_logger import NetworkLogger
    net_log = NetworkLogger()
    entry = net_log.log(
        method="POST",
        url="http://target.ctf/transfer",
        status_code=200,
        bytes_len=128,
        elapsed_ms=14.5,
        req_headers={"Host": "target.ctf"},
        req_body="account=admin&amount=5000",
        resp_headers={"Content-Type": "text/html"},
        resp_body="Success"
    )
    assert entry.id == 1
    assert entry.method == "POST"
    assert len(net_log.entries) == 1

    # CSRF PoC test
    csrf_poc = generate_csrf_poc("POST", "http://target.ctf/transfer", {"account": "admin", "amount": "5000"})
    assert "<form id=\"csrf-form\" action=\"http://target.ctf/transfer\" method=\"POST\">" in csrf_poc
    assert "name=\"account\" value=\"admin\"" in csrf_poc
    assert "document.getElementById('csrf-form').submit();" in csrf_poc
    print("  ✓ Network logger recording and automated CSRF exploit generator passed!")

    print("\n=== [10] TESTING DOM TREE PARSER & HIDDEN ELEMENT DETECTOR ===")
    from ctf_devtools.dom_tree import build_dom_tree, format_tag_details, is_tag_hidden
    from textual.widgets import Tree
    from bs4 import BeautifulSoup
    
    sample_html = """
    <html>
      <body>
        <div id="visible-container">Hello</div>
        <div id="secret-flag" style="display:none" data-secret="CTF{dom_tree_hidden_flag}">
          <input type="hidden" name="vault_token" value="xyz999" />
        </div>
      </body>
    </html>
    """
    soup = BeautifulSoup(sample_html, 'html.parser')
    hidden_div = soup.find('div', id='secret-flag')
    assert is_tag_hidden(hidden_div) is True
    details = format_tag_details(hidden_div)
    assert "VISIBILITY: HIDDEN" in details
    assert "data-secret = 'CTF{dom_tree_hidden_flag}'" in details
    flags.scan(details)
    print("  ✓ DOM Tree element hierarchy, hidden element detector, and attribute parser passed!")

    print("\n=== [11] TESTING CURL WORKBENCH & TEMPLATES ===")
    from ctf_devtools.curl_runner import (
        CURL_TEMPLATES, render_curl_template, execute_curl_command,
        parse_curl_to_repeater, curl_to_python_script
    )
    assert len(CURL_TEMPLATES) >= 10
    rendered = render_curl_template(CURL_TEMPLATES[0]["cmd"], "http://127.0.0.1:8888", {"session": "test1234"})
    assert "http://127.0.0.1:8888/admin" in rendered

    # Test executing a real local curl request
    stdout, stderr, elapsed_ms, code = await execute_curl_command(f"curl -s -i http://127.0.0.1:{PORT}/")
    assert code == 0
    assert "200" in stdout
    assert "TODO" in stdout

    # Test parse curl to repeater
    parsed = parse_curl_to_repeater("curl -X POST 'http://127.0.0.1:8888/login' -H 'X-Admin: true' -d 'user=admin&pass=1337'")
    assert parsed["method"] == "POST"
    assert parsed["url"] == "http://127.0.0.1:8888/login"
    assert parsed["headers"]["X-Admin"] == "true"
    assert parsed["body"] == "user=admin&pass=1337"

    # Test convert curl to python
    py = curl_to_python_script("curl -X POST 'http://127.0.0.1:8888/login' -d 'user=admin'")
    assert "httpx.post" in py
    assert "verify=False" in py
    print("  ✓ cURL asynchronous execution, template rendering, repeater parsing, and python generation passed!")

    print("\n=== [12] TESTING SQLI WORKBENCH & WAF ENCODERS ===")
    from ctf_devtools.sqli_runner import (
        DBMS_PAYLOADS, tamper_inline_comments, tamper_mysql_version_comments,
        tamper_random_case, tamper_string_to_hex, tamper_string_to_char,
        tamper_url_encode, tamper_double_url_encode, generate_column_probe,
        generate_order_by_probe
    )
    assert "SQLite" in DBMS_PAYLOADS and "MySQL / MariaDB" in DBMS_PAYLOADS
    assert len(DBMS_PAYLOADS["SQLite"]) >= 5
    
    # Test tampers
    t_comm = tamper_inline_comments("SELECT * FROM users WHERE id=1")
    assert "SELECT/**/*/**/FROM/**/users/**/WHERE/**/id=1" == t_comm
    
    t_ver = tamper_mysql_version_comments("SELECT 1 UNION SELECT 2")
    assert "/*!50000SELECT*/" in t_ver and "/*!50000UNION*/" in t_ver
    
    t_hex = tamper_string_to_hex("SELECT * FROM users WHERE user='admin'")
    assert "user=0x61646d696e" in t_hex
    
    t_char = tamper_string_to_char("user='admin'", "MySQL")
    assert "CHAR(97,100,109,105,110)" in t_char
    
    probe_3 = generate_column_probe(3, "null", "SQLite")
    assert probe_3 == "' UNION SELECT null, null, null--"
    
    orderby_5 = generate_order_by_probe(5, "PostgreSQL")
    assert orderby_5 == "' ORDER BY 5--"
    print("  ✓ SQLi DBMS dialects, UNION column crafter, and WAF tamper encoders passed!")

    print("\n=== [13] TESTING PHP SANDBOX & CTF GADGETS ===")
    from ctf_devtools.php_runner import (
        PHP_MAGIC_HASHES, PHP_LFI_WRAPPERS, PHP_STARTER_TEMPLATES, execute_php_script
    )
    assert len(PHP_MAGIC_HASHES) >= 6
    assert len(PHP_LFI_WRAPPERS) >= 5
    assert "Web Shell / Command Execution" in PHP_STARTER_TEMPLATES
    
    # Execute a real local PHP script via subprocess
    php_code = '<?php echo "PHP_TEST_" . (7 * 7) . "_FLAG{php_sandbox_verified}"; ?>'
    stdout, stderr, elapsed_ms, code = await execute_php_script(php_code)
    assert code == 0, f"PHP failed with code {code}: {stderr}"
    assert "PHP_TEST_49_FLAG{php_sandbox_verified}" in stdout
    flags.scan(stdout)
    print("  ✓ PHP local sandbox execution, magic hashes, and LFI wrappers passed!")

    print("\n=== [14] TESTING UNIVERSAL PAYLOAD VAULT ===")
    from ctf_devtools.payload_vault import PAYLOAD_CATEGORIES, search_payloads
    assert len(PAYLOAD_CATEGORIES) >= 5
    xss_results = search_payloads("alert")
    assert len(xss_results) >= 3
    ssti_results = search_payloads("popen")
    assert len(ssti_results) >= 1
    shell_results = search_payloads("reverse shell")
    assert len(shell_results) >= 2
    print("  ✓ Universal Payload Vault search and category lookup passed!")

    print("\n=== [15] TESTING CROSS-PLATFORM COMPATIBILITY & VERSIONING ===")
    import ctf_devtools
    from ctf_devtools.platform_compat import get_default_downloads_dir, find_binary
    assert ctf_devtools.__version__ == "1.0.0"
    dl_dir = get_default_downloads_dir()
    assert dl_dir.exists() and dl_dir.is_dir()
    assert find_binary("python3") or find_binary("python")
    print("  ✓ Semantic versioning v1.0.0 and cross-platform compatibility passed!")

    print("\n=== [16] FLAG TRACKER SUMMARY ===")
    all_flags = flags.get_all_flags()
    print(f"  [+] Captured Flags Total: {len(all_flags)}")
    for f in all_flags:
        print(f"      • {f}")
    assert len(all_flags) >= 5
    print("\n>>> ALL 16 TEST SUITES PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    time.sleep(0.2)
    asyncio.run(run_tests())
