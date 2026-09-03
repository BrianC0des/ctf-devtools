"""Main Textual TUI Application for CTF DevTools with modern transparent aesthetics."""
import asyncio
import json
import re
import urllib.parse
import httpx

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header, Footer, TabbedContent, TabPane, Input, Button,
    TextArea, DataTable, Static, Log, Label, Tree
)
from textual.widgets._tree import TreeNode
from textual.binding import Binding

from .flags import FlagTracker
from .decoders import (
    base64_decode, base64_encode, hex_decode, hex_encode,
    url_decode, url_encode, rot13, inspect_jwt,
    unpack_flask_session, identify_hash
)
from .scanner import CTFScanner
from .dom_analyzer import DOMAnalyzer
from .crawler import CTFCrawler
from .repeater import RepeaterEngine, has_fuzz_marker
from .comments_gatherer import CommentsGatherer
from .storage_mgr import CookieAndStorageManager
from .oob_listener import OOBListener, OOBRequest
from .websocket_mgr import WebSocketManager, WSFrame
from .session import SessionManager
from .network_logger import NetworkLogger, NetworkEntry
from .js_console import JSConsoleEngine, deobfuscate_javascript, generate_csrf_poc
from .dom_tree import build_dom_tree, format_tag_details, is_tag_hidden
from .curl_runner import (
    CURL_TEMPLATES, render_curl_template, execute_curl_command,
    parse_curl_to_repeater, curl_to_python_script, format_curl_command
)
from . import __version__
from .sqli_runner import (
    DBMS_PAYLOADS, tamper_inline_comments, tamper_mysql_version_comments,
    tamper_random_case, tamper_space_to_newline, tamper_space_to_tab,
    tamper_string_to_hex, tamper_string_to_char, tamper_url_encode,
    tamper_double_url_encode, generate_column_probe, generate_order_by_probe
)
from .php_runner import (
    PHP_MAGIC_HASHES, PHP_LFI_WRAPPERS, PHP_STARTER_TEMPLATES, execute_php_script
)
from .payload_vault import PAYLOAD_CATEGORIES, search_payloads
from .platform_compat import get_default_downloads_dir, init_platform

APP_CSS = """
Screen {
    background: transparent;
    color: #c0caf5;
}

#top-bar {
    height: 3;
    padding: 0 1;
    margin: 0;
    background: transparent;
    border-bottom: solid #3b4261;
    align: left middle;
}

#target-badge {
    background: #24283b;
    color: #7aa2f7;
    text-style: bold;
    padding: 0 1;
    margin-right: 1;
    height: 1;
    border: none;
}

#target-url {
    width: 42%;
    border: none;
    height: 1;
    background: #1f2335;
    color: #ffffff;
    padding: 0 1;
    margin: 0;
}

#target-url:focus {
    background: #24283b;
    color: #7dcfff;
}

.btn-primary {
    background: #7aa2f7;
    color: #11121d;
    text-style: bold;
    border: none;
    height: 1;
    min-width: 12;
    margin: 0 1;
    padding: 0 1;
}

.btn-primary:hover {
    background: #89b4fa;
    color: #000000;
    text-style: bold;
}

.btn-accent {
    background: #73daca;
    color: #11121d;
    text-style: bold;
    border: none;
    height: 1;
    min-width: 12;
    margin: 0 1;
    padding: 0 1;
}

.btn-accent:hover {
    background: #a6e3a1;
    color: #000000;
    text-style: bold;
}

.btn-secondary {
    background: #24283b;
    color: #c0caf5;
    text-style: bold;
    border: none;
    height: 1;
    min-width: 10;
    margin: 0 1;
    padding: 0 1;
}

.btn-secondary:hover {
    background: #414868;
    color: #ffffff;
    text-style: bold;
}

.flag-badge {
    background: #24283b;
    color: #73daca;
    text-style: bold;
    border: none;
    padding: 0 1;
    height: 1;
    margin: 0 1;
}

#inp-session {
    width: 14;
    border: none;
    height: 1;
    background: #1f2335;
    color: #ffffff;
    padding: 0 1;
    margin: 0 1;
}

#inp-session:focus {
    background: #24283b;
}

/* Tabbed Content */
TabbedContent {
    background: transparent;
    padding: 0;
    margin: 0;
    height: 1fr;
}

TabPane {
    background: transparent;
    padding: 0;
    height: 1fr;
}

Tabs {
    background: transparent;
    height: 2;
    border-bottom: solid #3b4261;
}

Tab {
    background: transparent;
    color: #565f89;
    text-style: bold;
    padding: 0 2;
    height: 2;
    border: none;
}

Tab:hover {
    color: #bb9af7;
    background: #24283b;
}

Tab.-active {
    color: #7aa2f7;
    background: transparent;
    border-bottom: tall #7aa2f7;
    text-style: bold;
}

/* Card & Panels */
.card-panel {
    border: round #3b4261;
    background: transparent;
    padding: 1;
    margin: 0 1 0 0;
    height: 1fr;
}

.card-title {
    color: #7dcfff;
    text-style: bold;
    padding-bottom: 1;
}

.pane-half {
    width: 50%;
    height: 1fr;
}

.sub-bar {
    height: 1;
    margin-bottom: 1;
    align-vertical: middle;
}

/* Text Areas & Inputs */
TextArea {
    border: round #3b4261;
    background: transparent;
    color: #c0caf5;
    height: 1fr;
}

TextArea:focus {
    border: round #7aa2f7;
}

Input {
    height: 1;
    border: none;
    background: #1f2335;
    color: #c0caf5;
    padding: 0 1;
    margin: 0;
}

Input:focus {
    background: #292e42;
    color: #7dcfff;
}

#rep-method {
    width: 8;
    margin-right: 1;
}

#inp-dom-search {
    width: 45;
    margin-right: 1;
}

#rep-url {
    width: 1fr;
}

#ws-url {
    width: 1fr;
    margin-right: 1;
}

#ws-payload {
    width: 1fr;
    margin-right: 1;
}

#oob-port {
    width: 10;
    margin-right: 1;
}

#inp-cookie-name {
    width: 14;
    margin-right: 1;
}

#inp-cookie-val {
    width: 1fr;
    margin-right: 1;
}

#inp-hdr-name {
    width: 18;
    margin-right: 1;
}

#inp-hdr-val {
    width: 1fr;
    margin-right: 1;
}

#rep-fuzz-range {
    width: 14;
    margin-right: 1;
}

/* Tables */
DataTable {
    background: transparent;
    border: round #3b4261;
    height: 1fr;
}

DataTable:focus {
    border: round #7aa2f7;
}

DataTable > .datatable--header {
    background: #24283b;
    color: #7dcfff;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #364a82;
    color: #ffffff;
    text-style: bold;
}

/* Tree */
Tree {
    background: transparent;
    border: round #3b4261;
    height: 1fr;
}

Tree:focus {
    border: round #7aa2f7;
}

Tree > .tree--cursor {
    background: #364a82;
    color: #ffffff;
    text-style: bold;
}

.status-alert {
    color: #73daca;
    text-style: bold;
    padding: 0 1;
}

.status-meta {
    color: #7dcfff;
    text-style: bold;
    height: 1;
    margin-bottom: 0;
}

.h-short {
    height: 6;
    min-height: 4;
}

Footer {
    background: transparent;
    color: #565f89;
}
"""

class CTFDevToolsApp(App):
    CSS = APP_CSS
    TITLE = f"CTF DevTools v{__version__}"
    SUB_TITLE = "Terminal Offensive Workstation"
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+a", "analyze_target", "Analyze", show=True),
        Binding("ctrl+s", "send_repeater", "Send", show=True),
        Binding("ctrl+r", "run_scanner", "Recon", show=True),
        Binding("ctrl+j", "run_js", "Run JS", show=True),
        Binding("ctrl+e", "exec_curl", "Run cURL", show=True),
        Binding("ctrl+b", "exec_php", "Run PHP", show=True),
    ]

    def __init__(self, initial_url: str = "http://127.0.0.1:8000"):
        super().__init__()
        init_platform()
        self.initial_url = initial_url
        self.flag_tracker = FlagTracker()
        self.cookie_storage = CookieAndStorageManager()
        self.network_logger = NetworkLogger()
        self.repeater_engine = RepeaterEngine(self.flag_tracker, self.cookie_storage, self.network_logger)
        self.js_engine = JSConsoleEngine()
        self.session_mgr = SessionManager()
        self.oob_listener = None
        self.ws_mgr = None
        self.discovered_assets = []
        self.current_asset_url = ""
        self.current_asset_content = ""
        self.comments_gatherer = None
        self.raw_comments_report = ""
        self.probe_results = []
        self.current_probe_url = ""
        self.selected_network_entry = None
        self.current_html = ""
        self.dom_hidden_only = False
        self.selected_dom_tag = None
        self._debounce_task = None
        self.downloads_dir = get_default_downloads_dir()

        # SQLi state
        self.selected_dbms = "SQLite"
        self.sqli_column_count = 3
        self.active_sqli_templates = DBMS_PAYLOADS["SQLite"]

        # Payloads state
        self.active_payload_list = search_payloads("")

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="top-bar"):
            yield Label("TARGET", id="target-badge")
            yield Input(value=self.initial_url, placeholder="http://target.ctf:8080", id="target-url")
            yield Button(" Analyze", id="btn-analyze", classes="btn-primary")
            yield Button(" Recon", id="btn-recon-top", classes="btn-accent")
            yield Label(" 0 FLAGS", id="lbl-flags", classes="flag-badge")
            yield Input(value="challenge_1", placeholder="Session", id="inp-session")
            yield Button(" Save", id="btn-save-session", classes="btn-secondary")

        with TabbedContent(initial="tab-sources" if self.initial_url else "tab-recon"):
            # TAB 1: Recon & Sensitive Probes
            with TabPane(" Recon", id="tab-recon"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Sensitive Paths & Probes (Click/Arrow to View)", classes="card-title")
                        yield DataTable(id="tbl-recon")
                        yield Label(" Tech Stack & Disclosure Headers", classes="card-title")
                        yield TextArea(id="txt-tech-stack", read_only=True, classes="h-short")

                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Probe File Content Inspector", classes="card-title")
                        yield Label("Selected File: None", id="lbl-probe-file", classes="status-meta")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Fetch Full", id="btn-fetch-probe", classes="btn-primary")
                            yield Button(" To Repeater", id="btn-probe-rep", classes="btn-secondary")
                            yield Button(" cURL", id="btn-probe-curl", classes="btn-secondary")
                            yield Button(" Scan Secrets", id="btn-scan-probe", classes="btn-accent")
                        yield TextArea(id="txt-probe-content", read_only=True)

            # TAB 2: Elements (Full DOM Tree Inspector)
            with TabPane(" Elements", id="tab-elements"):
                with Vertical(classes="card-panel"):
                    with Horizontal(classes="sub-bar"):
                        yield Input(placeholder="Filter tag, id, class, or text (e.g. input, #secret, hidden)", id="inp-dom-search")
                        yield Button(" Filter", id="btn-dom-search", classes="btn-primary")
                        yield Button("🔒 Hidden Only", id="btn-dom-hidden", classes="btn-secondary")
                        yield Button(" Copy OuterHTML", id="btn-dom-copy", classes="btn-secondary")
                        yield Button(" Re-Parse", id="btn-dom-refresh", classes="btn-accent")
                    with Horizontal():
                        with Vertical(classes="pane-half"):
                            yield Label(" HTML DOM Tree (Click/Arrow to Inspect)", classes="card-title")
                            yield Tree("Document (Empty)", id="tree-dom")
                        with Vertical(classes="pane-half"):
                            yield Label("Selected Element Attributes & Flags:", classes="card-title")
                            yield TextArea(id="txt-node-attrs", read_only=True, classes="h-short")
                            yield Label("Raw Outer HTML:", classes="card-title")
                            yield TextArea(id="txt-node-html", read_only=True)

            # TAB 3: Comments & Secrets
            with TabPane(" Comments & Secrets", id="tab-dom"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Comments Gatherer (HTML + JS + CSS)", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Refresh", id="btn-gather-comments", classes="btn-primary")
                            yield Button(" Suspicious Only", id="btn-filter-comments", classes="btn-secondary")
                        yield TextArea(id="txt-comments", read_only=True)
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Forms & Hidden Inputs", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Generate CSRF PoC", id="btn-form-csrf", classes="btn-accent")
                        yield TextArea(id="txt-forms", read_only=True)

            # TAB 3: Sources & Loaded Files (.js, .css, .json, .map, docs)
            with TabPane(" Sources & Files", id="tab-sources"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Loaded Assets & Discovered Files", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Fetch / View", id="btn-fetch-asset", classes="btn-primary")
                            yield Button("⬇ Download", id="btn-download-asset", classes="btn-accent")
                            yield Button(" Scan Secrets", id="btn-scan-asset", classes="btn-secondary")
                            yield Button(" Probe .map", id="btn-probe-map", classes="btn-secondary")
                        yield DataTable(id="tbl-assets")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" File Inspector", id="lbl-asset-info", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" cURL", id="btn-asset-curl", classes="btn-secondary")
                            yield Button(" To Repeater", id="btn-asset-rep", classes="btn-secondary")
                        yield TextArea(id="txt-asset-content", read_only=True)

            # TAB 4: Storage & Cookies (Cookie Jar, Global Auth, Storage Harvester)
            with TabPane(" Storage & Cookies", id="tab-storage"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Active Cookie Jar (Auto-Captured & Decoded)", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Input(placeholder="Cookie Name", id="inp-cookie-name")
                            yield Input(placeholder="Value", id="inp-cookie-val")
                            yield Button(" Set", id="btn-set-cookie", classes="btn-primary")
                            yield Button(" Del", id="btn-del-cookie", classes="btn-secondary")
                            yield Button(" Decode", id="btn-decode-cookie", classes="btn-accent")
                        yield DataTable(id="tbl-cookies")
                        yield Label("Decoded Cookie Value (JWT / Flask / Base64):", classes="card-title")
                        yield TextArea(id="txt-cookie-decoded", read_only=True)

                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Global Auth Headers (Auto-Injected)", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Input(value="Authorization", placeholder="Header Name", id="inp-hdr-name")
                            yield Input(placeholder="Bearer token / 127.0.0.1", id="inp-hdr-val")
                            yield Button(" Set Header", id="btn-set-hdr", classes="btn-primary")
                            yield Button(" Clear", id="btn-del-hdr", classes="btn-secondary")
                        yield TextArea(id="txt-global-headers", read_only=True)
                        yield Label(" Client-Side Storage Harvester (localStorage / sessionStorage)", classes="card-title")
                        yield DataTable(id="tbl-storage")

            # TAB 5: Crawler & Spider
            with TabPane(" Crawler", id="tab-crawler"):
                with Horizontal(classes="sub-bar"):
                    yield Button(" Start Spider", id="btn-spider", classes="btn-primary")
                    yield Label("Recursively crawls internal routes and extracts JavaScript endpoints", classes="status-alert")
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Crawled Routes", classes="card-title")
                        yield DataTable(id="tbl-crawled")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Discovered API Endpoints", classes="card-title")
                        yield TextArea(id="txt-js-routes", read_only=True)

            # TAB 5: Repeater & Fuzzer
            with TabPane(" Repeater", id="tab-repeater"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Request Composer (Supports FUZZ / fzz)", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Input(value="GET", id="rep-method", placeholder="Method")
                            yield Input(value=self.initial_url, id="rep-url", placeholder="URL")
                        yield Label("Headers:")
                        yield TextArea("User-Agent: CTF-DevTools/1.0\nAccept: */*\n", id="rep-headers")
                        yield Label("Body:")
                        yield TextArea("", id="rep-body")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Send (Ctrl+S)", id="btn-rep-send", classes="btn-primary")
                            yield Button(" cURL", id="btn-rep-curl", classes="btn-secondary")
                            yield Button(" Python", id="btn-rep-python", classes="btn-secondary")
                            yield Button(" CSRF", id="btn-rep-csrf", classes="btn-secondary")
                            yield Input(value="0..30", placeholder="0..30 or list", id="rep-fuzz-range")
                            yield Button(" Fuzz (FUZZ)", id="btn-rep-fuzz", classes="btn-accent")
                    
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Response Inspector", classes="card-title")
                        yield Label("Status: - | Latency: - | Size: -", id="rep-meta")
                        yield Label("", id="rep-flag-alert", classes="status-alert")
                        yield Label("Headers:")
                        yield TextArea(id="rep-resp-headers", read_only=True)
                        yield Label("Body:")
                        yield TextArea(id="rep-resp-body", read_only=True)

            # TAB: cURL Workbench & Premade CTF Scripts
            with TabPane(" cURL", id="tab-curl"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" cURL Command Workshop", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Execute (Ctrl+E)", id="btn-curl-exec", classes="btn-primary")
                            yield Button("⇥ Format", id="btn-curl-fmt", classes="btn-secondary")
                            yield Button(" To Repeater", id="btn-curl-to-rep", classes="btn-secondary")
                            yield Button("🐍 To Python", id="btn-curl-to-py", classes="btn-secondary")
                            yield Button(" Clear", id="btn-curl-clear", classes="btn-secondary")
                        yield TextArea(f'curl -i -k "{self.initial_url}"', id="txt-curl-cmd")
                        with Horizontal(classes="sub-bar"):
                            yield Label(" CTF cURL Templates:", classes="card-title")
                            yield Button(" Load Template", id="btn-curl-load-tpl", classes="btn-accent")
                        yield DataTable(id="tbl-curl-templates")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Response & Execution Output", classes="card-title")
                        yield Label("Status: Ready | Latency: -- ms | Code: --", id="lbl-curl-meta", classes="status-meta")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Copy Command", id="btn-curl-copy-cmd", classes="btn-secondary")
                            yield Button(" Copy Output", id="btn-curl-copy-resp", classes="btn-secondary")
                            yield Button(" Scan Flags", id="btn-curl-scan-flags", classes="btn-accent")
                        yield TextArea(id="txt-curl-resp", read_only=True)

            # TAB: SQL Injection Workbench & WAF Encoders
            with TabPane("💉 SQLi", id="tab-sqli"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label("💉 SQLi Dialect & Attack Templates", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button("SQLite", id="btn-sqli-sqlite", classes="btn-primary")
                            yield Button("MySQL", id="btn-sqli-mysql", classes="btn-secondary")
                            yield Button("Postgres", id="btn-sqli-postgres", classes="btn-secondary")
                            yield Button("MSSQL", id="btn-sqli-mssql", classes="btn-secondary")
                            yield Button("Oracle", id="btn-sqli-oracle", classes="btn-secondary")
                        yield DataTable(id="tbl-sqli-templates")
                        with Horizontal(classes="sub-bar"):
                            yield Label("Column Fuzz:", classes="card-title")
                            yield Button("- Col", id="btn-sqli-col-dec", classes="btn-secondary")
                            yield Button("+ Col", id="btn-sqli-col-inc", classes="btn-secondary")
                            yield Button("⚡ UNION Probe", id="btn-sqli-gen-union", classes="btn-primary")
                            yield Button("⚡ ORDER BY", id="btn-sqli-gen-orderby", classes="btn-accent")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" SQL Payload & WAF Bypass Tamper", classes="card-title")
                        yield Label("Active DBMS: SQLite | Columns: 3", id="lbl-sqli-info", classes="status-meta")
                        yield TextArea("' UNION SELECT null,sqlite_version()--", id="txt-sqli-editor")
                        yield Label("WAF Tamper Encoders (Click to Transform):", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button("/**/ Space", id="btn-tamper-comment", classes="btn-secondary")
                            yield Button("/*!MySQL*/", id="btn-tamper-version", classes="btn-secondary")
                            yield Button("0xHex Str", id="btn-tamper-hex", classes="btn-secondary")
                            yield Button("CHAR()", id="btn-tamper-char", classes="btn-secondary")
                            yield Button("aLtErCaSe", id="btn-tamper-case", classes="btn-secondary")
                        with Horizontal(classes="sub-bar"):
                            yield Button("%0a Newline", id="btn-tamper-nl", classes="btn-secondary")
                            yield Button("%09 Tab", id="btn-tamper-tab", classes="btn-secondary")
                            yield Button("URL Enc", id="btn-tamper-url", classes="btn-secondary")
                            yield Button("Double URL", id="btn-tamper-durl", classes="btn-secondary")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" To Repeater", id="btn-sqli-to-rep", classes="btn-primary")
                            yield Button(" cURL", id="btn-sqli-to-curl", classes="btn-secondary")
                            yield Button("📋 Copy Payload", id="btn-sqli-copy", classes="btn-accent")

            # TAB: PHP Sandbox Environment & CTF Gadgets
            with TabPane("🐘 PHP", id="tab-php"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label("🐘 Interactive PHP Script Sandbox", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Run PHP (Ctrl+B)", id="btn-php-run", classes="btn-primary")
                            yield Button(" To Repeater", id="btn-php-to-rep", classes="btn-secondary")
                            yield Button(" Clear", id="btn-php-clear", classes="btn-secondary")
                            yield Button("📋 Copy Code", id="btn-php-copy", classes="btn-accent")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" WebShell", id="btn-php-tpl-shell", classes="btn-secondary")
                            yield Button(" POP Chain", id="btn-php-tpl-pop", classes="btn-secondary")
                            yield Button(" 0e Fuzzer", id="btn-php-tpl-hash", classes="btn-secondary")
                            yield Button(" Preload Bypass", id="btn-php-tpl-preload", classes="btn-secondary")
                        yield TextArea(PHP_STARTER_TEMPLATES["Web Shell / Command Execution"], id="txt-php-editor")
                        yield Label("Magic Hashes (0e... Loose Comparisons '=='):", classes="card-title")
                        yield DataTable(id="tbl-php-hashes")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Execution Output & Results", classes="card-title")
                        yield Label("PHP Status: Ready | Latency: -- ms", id="lbl-php-meta", classes="status-meta")
                        yield TextArea(id="txt-php-output", read_only=True)
                        yield Label("PHP LFI Wrappers & Filter Chains (Click to Load):", classes="card-title")
                        yield DataTable(id="tbl-php-wrappers")

            # TAB: Universal Payload Vault
            with TabPane("🎯 Payloads", id="tab-payloads"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label("🎯 Universal CTF Payload Vault", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Input(placeholder="Search payloads (xss, ssti, shell, bypass, aws...)", id="inp-payload-search")
                            yield Button(" Search", id="btn-payload-search", classes="btn-primary")
                            yield Button(" Reset", id="btn-payload-reset", classes="btn-secondary")
                        yield DataTable(id="tbl-payloads")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Selected Payload String", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" To Repeater", id="btn-payload-to-rep", classes="btn-primary")
                            yield Button(" cURL", id="btn-payload-to-curl", classes="btn-secondary")
                            yield Button("📋 Copy String", id="btn-payload-copy", classes="btn-accent")
                        yield TextArea(id="txt-payload-view", read_only=False)
                        yield Label("Description & Exploitation Notes:", classes="card-title")
                        yield TextArea(id="txt-payload-notes", read_only=True, classes="h-short")

            # TAB 6: Decoders (CyberChef-Lite)
            with TabPane(" Decoders", id="tab-decoders"):
                with Vertical(classes="card-panel"):
                    yield Label(" Input Payload / Token / Hash:", classes="card-title")
                    yield TextArea("", id="dec-input")
                    with Horizontal(classes="sub-bar"):
                        yield Button("B64 Dec", id="btn-b64-dec", classes="btn-secondary")
                        yield Button("B64 Enc", id="btn-b64-enc", classes="btn-secondary")
                        yield Button("URL Dec", id="btn-url-dec", classes="btn-secondary")
                        yield Button("URL Enc", id="btn-url-enc", classes="btn-secondary")
                        yield Button("Hex Dec", id="btn-hex-dec", classes="btn-secondary")
                        yield Button("Hex Enc", id="btn-hex-enc", classes="btn-secondary")
                        yield Button("ROT13", id="btn-rot13", classes="btn-secondary")
                        yield Button("JWT Parse", id="btn-jwt", classes="btn-primary")
                        yield Button("Flask Cookie", id="btn-flask", classes="btn-accent")
                        yield Button("Hash ID", id="btn-hash", classes="btn-secondary")
                    yield Label(" Decoded Output:", classes="card-title")
                    yield TextArea(id="dec-output", read_only=True)

            # TAB 7: WebSockets
            with TabPane(" WebSockets", id="tab-ws"):
                with Vertical(classes="card-panel"):
                    yield Label(" WebSocket Stream", classes="card-title")
                    with Horizontal(classes="sub-bar"):
                        yield Input(value="ws://127.0.0.1:8000/ws", id="ws-url")
                        yield Button(" Connect", id="btn-ws-connect", classes="btn-primary")
                        yield Button(" Disconnect", id="btn-ws-disconnect", classes="btn-secondary")
                    yield Label("Live Frames:")
                    yield TextArea(id="txt-ws-log", read_only=True)
                    yield Label("Send Frame:")
                    with Horizontal(classes="sub-bar"):
                        yield Input(value='{"action": "ping"}', id="ws-payload")
                        yield Button(" Send", id="btn-ws-send", classes="btn-primary")

            # TAB 8: OOB Callbacks & Flags
            with TabPane(" Callbacks", id="tab-oob"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Local OOB HTTP Listener", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Input(value="9999", id="oob-port", placeholder="Port")
                            yield Button(" Start", id="btn-oob-start", classes="btn-primary")
                            yield Button(" Stop", id="btn-oob-stop", classes="btn-secondary")
                        yield Label("Incoming Requests:")
                        yield DataTable(id="tbl-oob")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Captured Flags Archive", classes="card-title")
                        yield TextArea(id="txt-all-flags", read_only=True)

            # TAB 9: JS Console & Deobfuscator
            with TabPane(" Console", id="tab-js-console"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label(" Interactive JavaScript Editor", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" Run (Ctrl+J)", id="btn-js-run", classes="btn-primary")
                            yield Button(" Preload Scripts", id="btn-js-preload", classes="btn-secondary")
                            yield Button(" Deobfuscate", id="btn-js-deobf", classes="btn-secondary")
                            yield Button(" Clear", id="btn-js-clear", classes="btn-accent")
                        yield TextArea("// Type JS expressions, custom crypto solvers, or challenge functions here:\nconsole.log('Location:', location.href);\nconsole.log('Cookies:', document.cookie);\n", id="txt-js-input")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label("Terminal Output & Evaluated Result", classes="card-title")
                        yield Label("Runtime: Node.js (Sandbox Active)", id="lbl-js-status", classes="status-meta")
                        yield TextArea(id="txt-js-output", read_only=True)

            # TAB 10: Live Network Traffic History
            with TabPane("󰒋 Network", id="tab-network"):
                with Horizontal():
                    with Vertical(classes="card-panel pane-half"):
                        yield Label("󰒋 HTTP Traffic History", classes="card-title")
                        with Horizontal(classes="sub-bar"):
                            yield Button(" To Repeater", id="btn-net-rep", classes="btn-primary")
                            yield Button(" cURL", id="btn-net-curl", classes="btn-secondary")
                            yield Button(" CSRF PoC", id="btn-net-csrf", classes="btn-secondary")
                            yield Button(" Clear", id="btn-net-clear", classes="btn-accent")
                        yield DataTable(id="tbl-network")
                    with Vertical(classes="card-panel pane-half"):
                        yield Label("Request & Response Inspector", classes="card-title")
                        yield Label("Select any traffic row on the left to inspect", id="lbl-net-meta", classes="status-meta")
                        yield Label("Request Headers & Body:")
                        yield TextArea(id="txt-net-req", read_only=True, classes="h-short")
                        yield Label("Response Headers & Body:")
                        yield TextArea(id="txt-net-resp", read_only=True)

            # TAB 11: Notes & Scratchpad
            with TabPane(" Notes", id="tab-notes"):
                with Vertical(classes="card-panel"):
                    yield Label(" Challenge Notes & Scratchpad", classes="card-title")
                    yield TextArea("## Target Notes\n- Discovered endpoints:\n- User credentials:\n- Attack vectors:\n", id="txt-notes")

        yield Footer()

    def on_mount(self):
        # Setup Tables
        tbl_recon = self.query_one("#tbl-recon", DataTable)
        tbl_recon.add_columns("STATUS", "PATH", "SIZE", "FLAGS", "SNIPPET")
        
        tbl_crawled = self.query_one("#tbl-crawled", DataTable)
        tbl_crawled.add_columns("STATUS", "URL", "TYPE")

        tbl_assets = self.query_one("#tbl-assets", DataTable)
        tbl_assets.add_columns("TYPE", "PATH / URL")

        tbl_cookies = self.query_one("#tbl-cookies", DataTable)
        tbl_cookies.add_columns("NAME", "VALUE", "PATH", "HTTPONLY")

        tbl_storage = self.query_one("#tbl-storage", DataTable)
        tbl_storage.add_columns("API", "KEY", "VALUE", "SOURCE")

        tbl_oob = self.query_one("#tbl-oob", DataTable)
        tbl_oob.add_columns("TIME", "IP", "METHOD", "PATH", "BODY")
        tbl_network = self.query_one("#tbl-network", DataTable)
        tbl_network.add_columns("ID", "TIME", "METHOD", "STATUS", "BYTES", "MS", "URL")

        tbl_curl = self.query_one("#tbl-curl-templates", DataTable)
        tbl_curl.add_columns("CATEGORY", "TEMPLATE NAME", "DESCRIPTION")
        for t in CURL_TEMPLATES:
            tbl_curl.add_row(t["category"], t["name"], t["desc"])

        # SQLi Templates Table
        tbl_sqli = self.query_one("#tbl-sqli-templates", DataTable)
        tbl_sqli.add_columns("CATEGORY", "NAME", "PAYLOAD")
        self._populate_sqli_table("SQLite")

        # PHP Hashes and Wrappers Tables
        tbl_php_h = self.query_one("#tbl-php-hashes", DataTable)
        tbl_php_h.add_columns("ALGO", "INPUT", "HASH COLLISION", "DESC")
        for h in PHP_MAGIC_HASHES:
            tbl_php_h.add_row(h["algo"], h["input"], h["hash"][:24] + "...", h["desc"])

        tbl_php_w = self.query_one("#tbl-php-wrappers", DataTable)
        tbl_php_w.add_columns("NAME", "WRAPPER / PAYLOAD")
        for w in PHP_LFI_WRAPPERS:
            tbl_php_w.add_row(w["name"], w["wrapper"][:45] + "...")

        # Universal Payloads Table
        tbl_payloads = self.query_one("#tbl-payloads", DataTable)
        tbl_payloads.add_columns("CATEGORY", "TYPE", "NAME", "PAYLOAD")
        self._populate_payloads_table("")

        # Configure all DataTables for single-row selection mode
        for tbl in [
            tbl_recon, tbl_crawled, tbl_assets, tbl_cookies, tbl_storage,
            tbl_oob, tbl_network, tbl_curl, tbl_sqli, tbl_php_h,
            tbl_php_w, tbl_payloads
        ]:
            tbl.cursor_type = "row"

        # Automatically analyze target immediately on startup
        if self.initial_url and self.initial_url.strip().startswith(("http://", "https://")):
            asyncio.create_task(self.action_analyze_url())

    def _populate_sqli_table(self, dbms: str):
        tbl = self.query_one("#tbl-sqli-templates", DataTable)
        tbl.clear()
        self.selected_dbms = dbms
        self.active_sqli_templates = DBMS_PAYLOADS.get(dbms, DBMS_PAYLOADS["SQLite"])
        for item in self.active_sqli_templates:
            tbl.add_row(item["category"], item["name"], item["payload"][:40])

    def _populate_payloads_table(self, query: str = ""):
        tbl = self.query_one("#tbl-payloads", DataTable)
        tbl.clear()
        self.active_payload_list = search_payloads(query)
        for item in self.active_payload_list:
            tbl.add_row(item["category"], item["type"], item["name"], item["payload"][:40])

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target-url":
            asyncio.create_task(self.action_analyze_url())
        elif event.input.id == "inp-dom-search":
            self.action_search_dom_tree()
        elif event.input.id == "inp-payload-search":
            self.action_search_payload_vault()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "target-url":
            val = event.value.strip()
            if val.startswith(("http://", "https://")):
                if self._debounce_task and not self._debounce_task.done():
                    self._debounce_task.cancel()
                self._debounce_task = asyncio.create_task(self._auto_analyze_delayed(val))
        elif event.input.id == "inp-payload-search":
            self.action_search_payload_vault()

    def _handle_table_row_action(self, table_id: str, row_idx: int) -> None:
        if table_id == "tbl-assets":
            if 0 <= row_idx < len(self.discovered_assets):
                asset = self.discovered_assets[row_idx]
                asyncio.create_task(self.fetch_asset(asset["url"]))
        elif table_id == "tbl-cookies":
            self.action_decode_selected_cookie()
        elif table_id == "tbl-recon":
            self.display_selected_probe(row_idx)
        elif table_id == "tbl-network":
            self.display_selected_network_entry(row_idx)
        elif table_id == "tbl-curl-templates":
            self.load_selected_curl_template(row_idx)
        elif table_id == "tbl-sqli-templates":
            self.load_selected_sqli_template(row_idx)
        elif table_id == "tbl-php-wrappers":
            self.load_selected_php_wrapper(row_idx)
        elif table_id == "tbl-php-hashes":
            self.load_selected_php_hash(row_idx)
        elif table_id == "tbl-payloads":
            self.load_selected_payload_item(row_idx)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._handle_table_row_action(event.data_table.id, event.cursor_row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._handle_table_row_action(event.data_table.id, event.cursor_row)

    def on_data_table_cell_highlighted(self, event: DataTable.CellHighlighted) -> None:
        self._handle_table_row_action(event.data_table.id, event.coordinate.row)

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        self._handle_table_row_action(event.data_table.id, event.coordinate.row)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
        if event.node and getattr(event.node, "tree", None) and event.node.tree.id == "tree-dom":
            self.display_selected_dom_node(event.node)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.node and getattr(event.node, "tree", None) and event.node.tree.id == "tree-dom":
            self.display_selected_dom_node(event.node)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-analyze":
            await self.action_analyze_url()
        elif bid == "btn-recon-top":
            await self.action_run_scanner()
        # Recon & Probe buttons
        elif bid == "btn-fetch-probe":
            await self.action_fetch_selected_probe()
        elif bid == "btn-probe-rep":
            self.action_send_probe_to_repeater()
        elif bid == "btn-probe-curl":
            self.action_copy_probe_curl()
        elif bid == "btn-scan-probe":
            self.action_scan_probe_secrets()
        # DOM Elements buttons
        elif bid == "btn-dom-search":
            self.action_search_dom_tree()
        elif bid == "btn-dom-hidden":
            self.action_toggle_hidden_dom()
        elif bid == "btn-dom-copy":
            self.action_copy_dom_outer_html()
        elif bid == "btn-dom-refresh":
            self.action_refresh_dom_tree()
        elif bid == "btn-spider":
            await self.action_run_spider()
        elif bid == "btn-rep-send":
            await self.action_send_repeater()
        elif bid == "btn-rep-curl":
            self.action_copy_curl()
        elif bid == "btn-rep-python":
            self.action_copy_python()
        elif bid == "btn-rep-fuzz":
            await self.action_run_fuzzer()
        # cURL Workbench buttons
        elif bid == "btn-curl-fmt":
            ta = self.query_one("#txt-curl-cmd", TextArea)
            ta.text = format_curl_command(ta.text)
            self.notify("Formatted!")
        elif bid == "btn-curl-load-tpl":
            tbl = self.query_one("#tbl-curl-templates", DataTable)
            self.load_selected_curl_template(tbl.cursor_row)
        elif bid == "btn-curl-exec":
            await self.action_exec_curl()
        elif bid == "btn-curl-to-rep":
            self.action_curl_to_repeater()
        elif bid == "btn-curl-to-py":
            self.action_curl_to_python()
        elif bid == "btn-curl-clear":
            self.query_one("#txt-curl-cmd", TextArea).text = ""
        elif bid == "btn-curl-copy-cmd":
            self.action_copy_curl_command()
        elif bid == "btn-curl-copy-resp":
            self.action_copy_curl_response()
        elif bid == "btn-curl-scan-flags":
            self.action_scan_curl_flags()
        # SQLi Workbench buttons
        elif bid == "btn-sqli-sqlite":
            self._select_dbms("SQLite")
        elif bid == "btn-sqli-mysql":
            self._select_dbms("MySQL / MariaDB")
        elif bid == "btn-sqli-postgres":
            self._select_dbms("PostgreSQL")
        elif bid == "btn-sqli-mssql":
            self._select_dbms("MSSQL")
        elif bid == "btn-sqli-oracle":
            self._select_dbms("Oracle")
        elif bid == "btn-sqli-col-inc":
            self.sqli_column_count += 1
            self._update_sqli_info()
        elif bid == "btn-sqli-col-dec":
            self.sqli_column_count = max(1, self.sqli_column_count - 1)
            self._update_sqli_info()
        elif bid == "btn-sqli-gen-union":
            probe = generate_column_probe(self.sqli_column_count, "null", self.selected_dbms)
            self.query_one("#txt-sqli-editor", TextArea).text = probe
            self.notify(f"Generated {self.sqli_column_count}-column UNION probe!")
        elif bid == "btn-sqli-gen-orderby":
            probe = generate_order_by_probe(self.sqli_column_count, self.selected_dbms)
            self.query_one("#txt-sqli-editor", TextArea).text = probe
            self.notify(f"Generated ORDER BY {self.sqli_column_count} probe!")
        elif bid == "btn-tamper-comment":
            self._tamper_active_sqli(tamper_inline_comments, "/**/ Space")
        elif bid == "btn-tamper-version":
            self._tamper_active_sqli(tamper_mysql_version_comments, "/*!MySQL*/")
        elif bid == "btn-tamper-hex":
            self._tamper_active_sqli(tamper_string_to_hex, "0xHex String")
        elif bid == "btn-tamper-char":
            self._tamper_active_sqli(lambda q: tamper_string_to_char(q, self.selected_dbms), "CHAR()")
        elif bid == "btn-tamper-case":
            self._tamper_active_sqli(tamper_random_case, "Random Case")
        elif bid == "btn-tamper-nl":
            self._tamper_active_sqli(tamper_space_to_newline, "%0a Newline")
        elif bid == "btn-tamper-tab":
            self._tamper_active_sqli(tamper_space_to_tab, "%09 Tab")
        elif bid == "btn-tamper-url":
            self._tamper_active_sqli(tamper_url_encode, "URL Encode")
        elif bid == "btn-tamper-durl":
            self._tamper_active_sqli(tamper_double_url_encode, "Double URL Encode")
        elif bid == "btn-sqli-to-rep":
            self.action_sqli_to_repeater()
        elif bid == "btn-sqli-to-curl":
            self.action_sqli_to_curl()
        elif bid == "btn-sqli-copy":
            self.action_copy_sqli_payload()
        # PHP Sandbox buttons
        elif bid == "btn-php-run":
            await self.action_exec_php()
        elif bid == "btn-php-to-rep":
            self.action_php_to_repeater()
        elif bid == "btn-php-clear":
            self.query_one("#txt-php-editor", TextArea).text = ""
        elif bid == "btn-php-copy":
            self.action_copy_php_code()
        elif bid == "btn-php-tpl-shell":
            self.query_one("#txt-php-editor", TextArea).text = PHP_STARTER_TEMPLATES["Web Shell / Command Execution"]
            self.notify("Loaded Web Shell template")
        elif bid == "btn-php-tpl-pop":
            self.query_one("#txt-php-editor", TextArea).text = PHP_STARTER_TEMPLATES["POP Chain & Object Serializer"]
            self.notify("Loaded POP Chain template")
        elif bid == "btn-php-tpl-hash":
            self.query_one("#txt-php-editor", TextArea).text = PHP_STARTER_TEMPLATES["Loose Type / Hash Crack Generator"]
            self.notify("Loaded 0e... Hash Fuzzer template")
        elif bid == "btn-php-tpl-preload":
            self.query_one("#txt-php-editor", TextArea).text = PHP_STARTER_TEMPLATES["Disabled Functions Bypass (LD_PRELOAD)"]
            self.notify("Loaded LD_PRELOAD bypass template")
        # Payload Vault buttons
        elif bid == "btn-payload-search":
            self.action_search_payload_vault()
        elif bid == "btn-payload-reset":
            self.query_one("#inp-payload-search", Input).value = ""
            self._populate_payloads_table("")
        elif bid == "btn-payload-to-rep":
            self.action_payload_to_repeater()
        elif bid == "btn-payload-to-curl":
            self.action_payload_to_curl()
        elif bid == "btn-payload-copy":
            self.action_copy_payload_string()
        # Sources & Asset buttons
        elif bid == "btn-fetch-asset":
            await self.action_fetch_selected_asset()
        elif bid == "btn-download-asset":
            await self.action_download_selected_asset()
        elif bid == "btn-scan-asset":
            self.action_scan_asset_secrets()
        elif bid == "btn-probe-map":
            await self.action_probe_source_map()
        elif bid == "btn-asset-curl":
            self.action_copy_asset_curl()
        elif bid == "btn-asset-rep":
            self.action_send_asset_to_repeater()
        # Comments gatherer buttons
        elif bid == "btn-gather-comments":
            await self.action_refresh_comments()
        elif bid == "btn-filter-comments":
            self.action_filter_suspicious_comments()
        # Storage & Cookie buttons
        elif bid == "btn-set-cookie":
            self.action_set_cookie()
        elif bid == "btn-del-cookie":
            self.action_delete_cookie()
        elif bid == "btn-decode-cookie":
            self.action_decode_selected_cookie()
        elif bid == "btn-set-hdr":
            self.action_set_global_header()
        elif bid == "btn-del-hdr":
            self.action_clear_global_headers()
        # Decoder buttons
        elif bid == "btn-b64-dec":
            self.handle_decode(base64_decode)
        elif bid == "btn-b64-enc":
            self.handle_decode(base64_encode)
        elif bid == "btn-url-dec":
            self.handle_decode(url_decode)
        elif bid == "btn-url-enc":
            self.handle_decode(url_encode)
        elif bid == "btn-hex-dec":
            self.handle_decode(hex_decode)
        elif bid == "btn-hex-enc":
            self.handle_decode(hex_encode)
        elif bid == "btn-rot13":
            self.handle_decode(rot13)
        elif bid == "btn-jwt":
            self.handle_jwt()
        elif bid == "btn-flask":
            self.handle_flask()
        elif bid == "btn-hash":
            self.handle_hash()
        # WebSocket buttons
        elif bid == "btn-ws-connect":
            await self.action_ws_connect()
        elif bid == "btn-ws-disconnect":
            await self.action_ws_disconnect()
        elif bid == "btn-ws-send":
            await self.action_ws_send()
        # OOB listener
        elif bid == "btn-oob-start":
            await self.action_oob_start()
        elif bid == "btn-oob-stop":
            await self.action_oob_stop()
        elif bid == "btn-save-session":
            self.action_save_session()
        # JS Console buttons
        elif bid == "btn-js-run":
            await self.action_run_js()
        elif bid == "btn-js-preload":
            await self.action_preload_target_scripts()
        elif bid == "btn-js-deobf":
            self.action_deobfuscate_js()
        elif bid == "btn-js-clear":
            self.action_clear_js_output()
        # Network History buttons
        elif bid == "btn-net-clear":
            self.action_clear_network_history()
        elif bid == "btn-net-rep":
            self.action_send_network_to_repeater()
        elif bid == "btn-net-curl":
            self.action_copy_network_curl()
        elif bid == "btn-net-csrf":
            self.action_generate_network_csrf()
        # CSRF PoC buttons
        elif bid == "btn-form-csrf":
            self.action_generate_form_csrf()
        elif bid == "btn-rep-csrf":
            self.action_generate_repeater_csrf()

    async def action_analyze_url(self):
        url = self.query_one("#target-url", Input).value.strip()
        if not url:
            return
        
        self.query_one("#rep-url", Input).value = url
        self.notify(f"Analyzing {url}...", timeout=2)
        resp = await self.repeater_engine.send_request("GET", url, {"User-Agent": "CTF-DevTools/1.0"})

        # Check for connection failure (e.g. expired challenge port)
        if resp.status_code == 0:
            self.query_one("#rep-meta", Label).update(f"[!] Connection Refused / Server Offline")
            self.query_one("#rep-resp-body", TextArea).text = (
                f"[!] FAILED TO CONNECT TO: {url}\n\n"
                f"Error: {resp.body}\n\n"
                "Possible causes:\n"
                "1. If this is a CTF challenge instance (e.g. picoCTF), the container port may have timed out.\n"
                "2. Check your network connection or verify the target port.\n"
                "3. You can paste the active URL into the top bar, and DevTools will auto-analyze immediately!"
            )
            self.notify(f"Connection failed to {url}! Check if challenge container is running.", severity="error", timeout=6)
            return

        self.current_html = resp.body
        self.action_refresh_dom_tree()
        self.flag_tracker.scan(resp.body)
        for h, v in resp.headers.items():
            self.flag_tracker.scan(f"{h}: {v}")
        self.update_flag_display()

        self.query_one("#rep-meta", Label).update(
            f"Status: {resp.status_code} | Latency: {resp.elapsed_ms}ms | Size: {resp.content_length} bytes"
        )
        self.query_one("#rep-resp-headers", TextArea).text = json.dumps(resp.headers, indent=2)
        self.query_one("#rep-resp-body", TextArea).text = resp.body[:10000]

        if resp.flags:
            self.query_one("#rep-flag-alert", Label).update(f"\uf024 FLAG FOUND: {', '.join(resp.flags)}")
        else:
            self.query_one("#rep-flag-alert", Label).update("")

        # 1. Immediate DOM & Forms extraction (0ms latency)
        dom = DOMAnalyzer(resp.body, base_url=url)

        forms = dom.extract_forms()
        form_lines = []
        for idx, f in enumerate(forms, 1):
            form_lines.append(f"Form #{idx}: [{f['method']}] Action: {f['action']}")
            for inp in f["inputs"]:
                attrs = []
                if inp["hidden"]:
                    attrs.append("HIDDEN")
                if inp["disabled"]:
                    attrs.append("DISABLED")
                attr_str = f" [{', '.join(attrs)}]" if attrs else ""
                form_lines.append(f"  • {inp['name']} ({inp['type']}){attr_str} = '{inp['value']}'")
        self.query_one("#txt-forms", TextArea).text = "\n".join(form_lines) if form_lines else "No forms found."

        # 2. Immediate Sources & Files table population
        assets = dom.extract_assets()
        self.discovered_assets = assets
        tbl_assets = self.query_one("#tbl-assets", DataTable)
        tbl_assets.clear()
        for a in assets:
            tbl_assets.add_row(a["type"], a["path"])

        # 3. Update cookies and harvest client-side storage from HTML
        self.update_cookies_display()
        self.cookie_storage.harvest_storage_from_code(resp.body, url)
        self.update_storage_display()

        # 4. Automatically fetch and inspect the first file
        if assets:
            asyncio.create_task(self.fetch_asset(assets[0]["url"]))

        # 5. Asynchronously gather external comments in background without blocking
        asyncio.create_task(self._gather_comments_background(url, resp.body))

        # 5. Start recon scanner asynchronously in background
        asyncio.create_task(self.action_run_scanner())

    async def _gather_comments_background(self, url: str, html_body: str):
        cg = CommentsGatherer(url, self.flag_tracker)
        self.comments_gatherer = cg
        await cg.gather_all(html_body)
        self.raw_comments_report = cg.format_report()
        self.query_one("#txt-comments", TextArea).text = self.raw_comments_report
        self.update_flag_display()

    async def action_run_scanner(self):
        url = self.query_one("#target-url", Input).value.strip()
        if not url:
            return
        scanner = CTFScanner(url, self.flag_tracker, cookie_storage=self.cookie_storage)
        tbl = self.query_one("#tbl-recon", DataTable)
        tbl.clear()
        self.probe_results = []

        def on_progress(idx, total, res):
            flags_str = ", ".join(res.flags) if res.flags else "-"
            tbl.add_row(
                str(res.status_code),
                res.path,
                f"{res.content_length} B",
                flags_str,
                res.snippet[:40]
            )
            self.probe_results.append(res)
            self.update_flag_display()
            if len(self.probe_results) == 1:
                self.display_selected_probe(0)

        results = await scanner.scan_all(on_progress=on_progress)
        self.probe_results = results
        tech_lines = [f"{k.upper()}: {v}" for k, v in scanner.tech_stack.items()]
        self.query_one("#txt-tech-stack", TextArea).text = "\n".join(tech_lines) if tech_lines else "No disclosure headers."
        if self.probe_results and not self.current_probe_url:
            self.display_selected_probe(0)

    def display_selected_probe(self, row_idx: int = -1):
        tbl = self.query_one("#tbl-recon", DataTable)
        if row_idx < 0:
            row_idx = tbl.cursor_row
        if not (0 <= row_idx < len(self.probe_results)):
            return
        res = self.probe_results[row_idx]
        self.current_probe_url = res.url
        self.current_probe_content = res.body or res.snippet
        
        lbl = self.query_one("#lbl-probe-file", Label)
        flag_indicator = f" [ FLAG FOUND]" if res.flags else ""
        lbl.update(f"Selected: {res.path} [{res.status_code}] ({res.content_length} B){flag_indicator}")
        
        viewer = self.query_one("#txt-probe-content", TextArea)
        flags_banner = f"🚩 FLAGS DETECTED: {', '.join(res.flags)}\n\n" if res.flags else ""
        body_to_show = res.body if res.body else f"[Preview Snippet]:\n{res.snippet}\n\n(Click 'Fetch Full' to retrieve entire content)"
        viewer.text = f"{flags_banner}{body_to_show}"

    async def action_fetch_selected_probe(self):
        if not self.current_probe_url:
            self.notify("Select a probe row first", severity="warning")
            return
        self.notify(f"Fetching {self.current_probe_url}...", timeout=2)
        resp = await self.repeater_engine.send_request("GET", self.current_probe_url, {"User-Agent": "CTF-DevTools/1.0"})
        self.current_probe_content = resp.body
        flags_banner = f"🚩 FLAGS DETECTED: {', '.join(resp.flags)}\n\n" if resp.flags else ""
        self.query_one("#txt-probe-content", TextArea).text = f"{flags_banner}{resp.body}"
        self.notify(f"Fetched {resp.content_length} bytes ({resp.status_code})")

    def action_send_probe_to_repeater(self):
        if not self.current_probe_url:
            self.notify("Select a probe row first", severity="warning")
            return
        self.query_one("#rep-url", Input).value = self.current_probe_url
        self.query_one("#rep-method", Input).value = "GET"
        self.query_one(TabbedContent).active = "tab-repeater"
        self.notify(f"Sent {self.current_probe_url} to Repeater!")

    def action_copy_probe_curl(self):
        if not self.current_probe_url:
            self.notify("Select a probe row first", severity="warning")
            return
        cmd = f"curl -s -i {self.current_probe_url}"
        try:
            import shutil, subprocess
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=cmd.encode(), check=False)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=cmd.encode(), check=False)
        except Exception:
            pass
        self.notify(f"Copied cURL: {cmd}")

    def action_scan_probe_secrets(self):
        content = self.current_probe_content
        if not content:
            self.notify("Select or fetch a probe first", severity="warning")
            return
        patterns = [
            ("Flag Pattern", r"(?:flag|ctf)\{[^\s\"'<>]+\}"),
            ("Partial Flag", r"picoCTF\{[^\s\"'<>]+"),
            ("API Key / Token", r"(?:api[_-]?key|secret|token|password|auth)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{8,})[\"']"),
            ("Endpoint / Route", r"[\"'](/(?:api|v[0-9]|auth|admin|debug|users)[a-zA-Z0-9_\-\.\/]+)[\"']"),
            ("Disallowed Route", r"Disallow:\s*([^\s]+)"),
        ]
        hits = []
        for name, pat in patterns:
            matches = re.findall(pat, content, re.I)
            for m in matches:
                val = m if isinstance(m, str) else m[0]
                hits.append(f"• [{name}]: {val}")
        viewer = self.query_one("#txt-probe-content", TextArea)
        hits_text = "\n".join(hits) if hits else "No obvious hardcoded secrets or routes detected."
        viewer.text = (
            f"=== SCAN RESULTS FOR {self.current_probe_url} ===\n\n"
            + hits_text
            + "\n\n=== FULL RAW CONTENT BELOW ===\n\n"
            + content
        )
        self.notify(f"Found {len(hits)} interesting pattern(s)")

    async def action_run_spider(self):
        url = self.query_one("#target-url", Input).value.strip()
        if not url:
            return
        crawler = CTFCrawler(url, self.flag_tracker, max_depth=2, max_pages=30)
        res = await crawler.crawl()
        
        tbl = self.query_one("#tbl-crawled", DataTable)
        tbl.clear()
        for ep in res["discovered"]:
            tbl.add_row(str(ep.status), ep.url, ep.content_type[:20])
        
        self.query_one("#txt-js-routes", TextArea).text = "\n".join(res["js_endpoints"]) if res["js_endpoints"] else "No JS API routes found."
        self.update_flag_display()

    async def action_fetch_selected_asset(self):
        tbl = self.query_one("#tbl-assets", DataTable)
        row_idx = tbl.cursor_row
        if 0 <= row_idx < len(self.discovered_assets):
            asset = self.discovered_assets[row_idx]
            await self.fetch_asset(asset["url"])
        elif self.discovered_assets:
            await self.fetch_asset(self.discovered_assets[0]["url"])
        else:
            self.notify("No assets discovered yet. Click Analyze first.", severity="warning")

    # Download directory — all downloads are restricted here
    DOWNLOAD_DIR = "/home/devchan/CTF/sandbox/ctf-dev-downloads"

    async def action_download_selected_asset(self):
        """Download the selected asset to DOWNLOAD_DIR as binary, preserving original bytes."""
        import os, urllib.parse, re as _re, pathlib

        tbl = self.query_one("#tbl-assets", DataTable)
        row_idx = tbl.cursor_row

        # Resolve URL from selected row or current asset
        url = None
        if 0 <= row_idx < len(self.discovered_assets):
            url = self.discovered_assets[row_idx]["url"]
        elif self.current_asset_url:
            url = self.current_asset_url

        if not url:
            self.notify("Select a file in the table first.", severity="warning")
            return

        # Derive a safe filename from the URL
        parsed_path = urllib.parse.urlparse(url).path
        raw_name = parsed_path.rstrip("/").split("/")[-1].split("?")[0] or "download"
        # Sanitize: keep alphanumeric, dots, dashes, underscores only
        safe_name = _re.sub(r"[^\w.\-]", "_", raw_name)[:120] or "download"

        dest_dir = pathlib.Path(self.DOWNLOAD_DIR)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / safe_name

        # Avoid overwriting: append counter if file already exists
        counter = 1
        stem = dest_path.stem
        suffix = dest_path.suffix
        while dest_path.exists():
            dest_path = dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        lbl = self.query_one("#lbl-asset-info", Label)
        lbl.update(f" Downloading: {safe_name}...")

        async with httpx.AsyncClient(verify=False, timeout=15.0,
                                     follow_redirects=True) as client:
            try:
                r = await client.get(url)
                dest_path.write_bytes(r.content)
                size_kb = len(r.content) / 1024
                content_type = r.headers.get("content-type", "unknown")
                lbl.update(
                    f" ⬇ Saved: {safe_name} ({size_kb:.1f} KB) → {self.DOWNLOAD_DIR}"
                )
                self.notify(
                    f"⬇ Downloaded: {safe_name}  ({size_kb:.1f} KB)",
                    timeout=5,
                )
                # Also scan text content for flags
                try:
                    text = r.content.decode("utf-8", errors="ignore")
                    flags = self.flag_tracker.scan(text)
                    if flags:
                        self.notify(f"🚩 FLAG in download: {', '.join(flags)}", severity="warning", timeout=8)
                    self.update_flag_display()
                except Exception:
                    pass
            except Exception as e:
                self.notify(f"Download failed: {e}", severity="error")
                lbl.update(f" Download failed: {e}")

    async def fetch_asset(self, url: str):
        self.current_asset_url = url
        lbl = self.query_one("#lbl-asset-info", Label)
        filename = url.split('/')[-1].split('?')[0] or url
        lbl.update(f" Fetching: {filename}...")
        viewer = self.query_one("#txt-asset-content", TextArea)
        viewer.text = f"Fetching asset from: {url}..."
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            try:
                r = await client.get(url)
                self.current_asset_content = r.text
                self.cookie_storage.harvest_storage_from_code(r.text, url)
                self.update_storage_display()
                flags = self.flag_tracker.scan(r.text)
                self.update_flag_display()
                flag_note = f" [ FLAG: {', '.join(flags)}]" if flags else ""
                lbl.update(f" {filename} ({len(r.content)} bytes){flag_note}")
                viewer.text = r.text[:50000]
            except Exception as e:
                viewer.text = f"[!] Failed to fetch asset: {e}"

    def action_scan_asset_secrets(self):
        content = self.current_asset_content
        if not content:
            self.notify("Fetch a file first to scan for secrets", severity="warning")
            return
        patterns = [
            ("Flag Pattern", r"(?:flag|ctf)\{[^\s\"'<>]+\}"),
            ("Partial Flag", r"picoCTF\{[^\s\"'<>]+"),
            ("API Key / Token", r"(?:api[_-]?key|secret|token|password|auth)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{8,})[\"']"),
            ("Endpoint / Route", r"[\"'](/(?:api|v[0-9]|auth|admin|debug|users)[a-zA-Z0-9_\-\.\/]+)[\"']"),
        ]
        hits = []
        for name, pat in patterns:
            matches = re.findall(pat, content, re.I)
            for m in matches:
                val = m if isinstance(m, str) else m[0]
                hits.append(f"• [{name}]: {val}")
        viewer = self.query_one("#txt-asset-content", TextArea)
        hits_text = "\n".join(hits) if hits else "No obvious hardcoded API keys or secrets detected."
        viewer.text = (
            f"=== SECRETS & ENDPOINTS SCANNED FROM {self.current_asset_url} ===\n\n"
            + hits_text
            + "\n\n=== FULL CONTENT BELOW ===\n\n"
            + content[:30000]
        )

    async def action_probe_source_map(self):
        if not self.current_asset_url:
            tbl = self.query_one("#tbl-assets", DataTable)
            row_idx = tbl.cursor_row
            if 0 <= row_idx < len(self.discovered_assets):
                self.current_asset_url = self.discovered_assets[row_idx]["url"]
        if not self.current_asset_url:
            self.notify("Select a JavaScript or CSS file first", severity="warning")
            return
        map_url = f"{self.current_asset_url}.map"
        viewer = self.query_one("#txt-asset-content", TextArea)
        viewer.text = f"Probing source map: {map_url}..."
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            try:
                r = await client.get(map_url)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        sources = data.get("sources", [])
                        sources_text = "\n• ".join(sources)
                        viewer.text = (
                            f"[+] SOURCE MAP FOUND! ({r.status_code} OK - {len(r.content)} bytes)\n\n"
                            f"Original Source Files ({len(sources)} files):\n• {sources_text}\n\n"
                            f"Raw Source Map Preview:\n{r.text[:20000]}"
                        )
                    except Exception:
                        viewer.text = f"[+] Source map returned ({len(r.content)} bytes):\n\n{r.text[:20000]}"
                else:
                    viewer.text = f"[-] Source map not found ({map_url} returned {r.status_code})."
            except Exception as e:
                viewer.text = f"[!] Source map probe error: {e}"

    def action_copy_asset_curl(self):
        if self.current_asset_url:
            curl_cmd = f"curl -i '{self.current_asset_url}'"
            self.query_one("#txt-asset-content", TextArea).text = f"[cURL Command]:\n{curl_cmd}"

    def action_send_asset_to_repeater(self):
        if self.current_asset_url:
            self.query_one("#rep-url", Input).value = self.current_asset_url
            self.query_one("#rep-method", Input).value = "GET"
            self.notify(f"Sent {self.current_asset_url} to Repeater")

    async def action_send_repeater(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text

        headers = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        resp = await self.repeater_engine.send_request(method, url, headers, body)
        self.query_one("#rep-meta", Label).update(
            f"Status: {resp.status_code} | Latency: {resp.elapsed_ms}ms | Size: {resp.content_length} bytes"
        )
        self.query_one("#rep-resp-headers", TextArea).text = json.dumps(resp.headers, indent=2)
        self.query_one("#rep-resp-body", TextArea).text = resp.body[:15000]

        if resp.flags:
            self.query_one("#rep-flag-alert", Label).update(f"\uf024 FLAG FOUND: {', '.join(resp.flags)}")
        else:
            self.query_one("#rep-flag-alert", Label).update("")

        self.update_flag_display()
        self.refresh_network_table()

    def action_copy_curl(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        headers = dict(line.split(":", 1) for line in headers_raw.splitlines() if ":" in line)
        curl_cmd = self.repeater_engine.to_curl(method, url, {k.strip(): v.strip() for k, v in headers.items()}, body)
        self.query_one("#rep-resp-body", TextArea).text = f"[cURL Command]:\n{curl_cmd}"

    def action_copy_python(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        headers = dict(line.split(":", 1) for line in headers_raw.splitlines() if ":" in line)
        py_code = self.repeater_engine.to_python_requests(method, url, {k.strip(): v.strip() for k, v in headers.items()}, body)
        self.query_one("#rep-resp-body", TextArea).text = f"[Python requests script]:\n\n{py_code}"

    async def action_run_fuzzer(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        headers = dict(line.split(":", 1) for line in headers_raw.splitlines() if ":" in line)

        has_fuzz = (
            has_fuzz_marker(url) or
            has_fuzz_marker(body) or
            has_fuzz_marker(headers_raw) or
            any(has_fuzz_marker(k) or has_fuzz_marker(v) for k, v in headers.items())
        )
        if not has_fuzz:
            self.notify("Add FUZZ or fzz in URL, Header, or Body (e.g. Cookie: name=FUZZ)", severity="warning", timeout=6)
            return

        raw_range = self.query_one("#rep-fuzz-range", Input).value.strip()
        payloads = []
        if ".." in raw_range:
            parts = raw_range.split("..", 1)
            try:
                start_n = int(parts[0].strip())
                end_n = int(parts[1].strip())
                payloads = [str(i) for i in range(start_n, end_n + 1)]
            except ValueError:
                pass
        elif "," in raw_range:
            payloads = [p.strip() for p in raw_range.split(",") if p.strip()]
        elif raw_range:
            payloads = [p.strip() for p in raw_range.split() if p.strip()]

        if not payloads:
            payloads = [str(i) for i in range(0, 31)]

        self.notify(f"Fuzzing {len(payloads)} payloads across FUZZ markers...", timeout=3)
        self.query_one("#rep-resp-body", TextArea).text = f"Running fuzzer across {len(payloads)} payloads...\n\nPayloads: {', '.join(payloads[:10])}..."

        fuzz_results = await self.repeater_engine.run_fuzzer(
            method, url, {k.strip(): v.strip() for k, v in headers.items()}, body, payloads
        )

        found_flags = []
        lines = [f"{'PAYLOAD':<14} {'STATUS':<8} {'BYTES':<10} {'MS':<10} {'FLAGS'}"]
        lines.append("-" * 65)
        for r in fuzz_results:
            flags_str = ", ".join(r.flags) if r.flags else ""
            if r.flags:
                found_flags.extend(r.flags)
            lines.append(f"{r.payload:<14} {r.status_code:<8} {str(r.length) + ' B':<10} {str(r.elapsed_ms) + 'ms':<10} {flags_str}")

        self.query_one("#rep-resp-body", TextArea).text = "\n".join(lines)
        if found_flags:
            self.query_one("#rep-flag-alert", Label).update(f" FLAG FOUND: {', '.join(found_flags)}")
            self.notify(f"Fuzzer discovered {len(found_flags)} flag(s)!", severity="information", timeout=6)
        else:
            self.query_one("#rep-flag-alert", Label).update("")
        self.update_flag_display()

    # Decoder helpers
    def handle_decode(self, func):
        text = self.query_one("#dec-input", TextArea).text
        try:
            self.query_one("#dec-output", TextArea).text = func(text)
        except Exception as e:
            self.query_one("#dec-output", TextArea).text = f"[Error]: {e}"

    def handle_jwt(self):
        text = self.query_one("#dec-input", TextArea).text
        res = inspect_jwt(text)
        self.query_one("#dec-output", TextArea).text = json.dumps(res, indent=2)

    def handle_flask(self):
        text = self.query_one("#dec-input", TextArea).text
        res = unpack_flask_session(text)
        self.query_one("#dec-output", TextArea).text = json.dumps(res, indent=2)

    def handle_hash(self):
        text = self.query_one("#dec-input", TextArea).text
        res = identify_hash(text)
        self.query_one("#dec-output", TextArea).text = "Likely Hash Types:\n• " + "\n• ".join(res)

    # WebSocket actions
    async def action_ws_connect(self):
        ws_url = self.query_one("#ws-url", Input).value.strip()
        log_box = self.query_one("#txt-ws-log", TextArea)

        def on_frame(f: WSFrame):
            log_box.text += f"[{f.timestamp}] [{f.direction}] {f.payload}\n"
            self.update_flag_display()

        self.ws_mgr = WebSocketManager(self.flag_tracker, on_frame=on_frame)
        try:
            await self.ws_mgr.connect(ws_url)
            log_box.text += f"[+] Connected to {ws_url}\n"
        except Exception as e:
            log_box.text += f"[!] Connection error: {e}\n"

    async def action_ws_disconnect(self):
        if self.ws_mgr:
            await self.ws_mgr.disconnect()
            self.query_one("#txt-ws-log", TextArea).text += "[-] Disconnected\n"

    async def action_ws_send(self):
        if self.ws_mgr and self.ws_mgr.is_connected:
            payload = self.query_one("#ws-payload", Input).value
            await self.ws_mgr.send(payload)

    # OOB actions
    async def action_oob_start(self):
        port_str = self.query_one("#oob-port", Input).value.strip()
        port = int(port_str) if port_str.isdigit() else 9999
        tbl = self.query_one("#tbl-oob", DataTable)

        def on_hit(req: OOBRequest):
            tbl.add_row(req.timestamp, req.client_ip, req.method, req.path, req.body[:30])

        self.oob_listener = OOBListener(port=port, on_hit=on_hit)
        try:
            await self.oob_listener.start()
            self.notify(f"OOB Listener started on port {port}")
        except Exception as e:
            self.notify(f"Failed to start OOB Listener: {e}", severity="error")

    async def action_oob_stop(self):
        if self.oob_listener:
            await self.oob_listener.stop()
            self.notify("OOB Listener stopped")

    def action_save_session(self):
        session_name = self.query_one("#inp-session", Input).value.strip() or "challenge"
        notes = self.query_one("#txt-notes", TextArea).text
        all_flags = self.flag_tracker.get_all_flags()
        data = {
            "session_name": session_name,
            "target_url": self.query_one("#target-url", Input).value,
            "flags": all_flags,
            "notes": notes,
        }
        sm = SessionManager(session_name)
        saved_path = sm.save(data)
        self.notify(f"Saved session to {saved_path}")

    async def action_refresh_comments(self):
        url = self.query_one("#target-url", Input).value.strip()
        if not url:
            return
        viewer = self.query_one("#txt-comments", TextArea)
        viewer.text = f"Gathering comments across HTML and linked assets from {url}..."
        resp = await self.repeater_engine.send_request("GET", url, {"User-Agent": "CTF-DevTools/1.0"})
        cg = CommentsGatherer(url, self.flag_tracker)
        self.comments_gatherer = cg
        await cg.gather_all(resp.body)
        self.raw_comments_report = cg.format_report()
        viewer.text = self.raw_comments_report
        self.update_flag_display()
        self.notify(f"Gathered {len(cg.comments)} comments!")

    def action_filter_suspicious_comments(self):
        if not self.comments_gatherer or not self.comments_gatherer.comments:
            return
        suspicious = [c for c in self.comments_gatherer.comments if c["suspicious"]]
        viewer = self.query_one("#txt-comments", TextArea)
        if not suspicious:
            viewer.text = "No suspicious comments detected."
            return
        lines = [f"=== SUSPICIOUS COMMENTS ONLY ({len(suspicious)} items) ===\n"]
        for c in suspicious:
            lines.append(f"┌─ [{c['file_type']}] {c['origin']}")
            lines.append(f"│  {c['comment']}")
            lines.append("└" + "─" * 60 + "\n")
        viewer.text = "\n".join(lines)

    # Storage & Cookies Methods
    def update_cookies_display(self):
        tbl = self.query_one("#tbl-cookies", DataTable)
        tbl.clear()
        for name, c in self.cookie_storage.cookies.items():
            tbl.add_row(c["name"], c["value"][:30], c["path"], str(c["httponly"]))
        if self.cookie_storage.cookies:
            self.action_decode_selected_cookie()

    def update_storage_display(self):
        tbl = self.query_one("#tbl-storage", DataTable)
        tbl.clear()
        for s in self.cookie_storage.harvested_storage:
            source_name = s["source"].split("/")[-1] or s["source"]
            tbl.add_row(s["api"], s["key"], s["value"][:30], source_name)

    def action_set_cookie(self):
        name = self.query_one("#inp-cookie-name", Input).value.strip()
        val = self.query_one("#inp-cookie-val", Input).value.strip()
        if not name:
            self.notify("Cookie Name is required", severity="warning")
            return
        self.cookie_storage.set_cookie(name, val)
        self.update_cookies_display()
        self.notify(f"Added Cookie: {name}={val[:15]}")

    def action_delete_cookie(self):
        tbl = self.query_one("#tbl-cookies", DataTable)
        row_idx = tbl.cursor_row
        names = list(self.cookie_storage.cookies.keys())
        if 0 <= row_idx < len(names):
            name = names[row_idx]
            self.cookie_storage.delete_cookie(name)
            self.update_cookies_display()
            self.notify(f"Deleted Cookie: {name}")

    def action_decode_selected_cookie(self):
        tbl = self.query_one("#tbl-cookies", DataTable)
        row_idx = tbl.cursor_row
        cookies_list = list(self.cookie_storage.cookies.values())
        viewer = self.query_one("#txt-cookie-decoded", TextArea)
        if 0 <= row_idx < len(cookies_list):
            c = cookies_list[row_idx]
            decoded = self.cookie_storage.decode_cookie_value(c["value"])
            viewer.text = f"=== COOKIE: {c['name']} ===\n\n{decoded}"
        elif cookies_list:
            c = cookies_list[0]
            decoded = self.cookie_storage.decode_cookie_value(c["value"])
            viewer.text = f"=== COOKIE: {c['name']} ===\n\n{decoded}"
        else:
            viewer.text = "No cookies in jar to decode."

    def action_set_global_header(self):
        name = self.query_one("#inp-hdr-name", Input).value.strip()
        val = self.query_one("#inp-hdr-val", Input).value.strip()
        if not name or not val:
            self.notify("Header name and value required", severity="warning")
            return
        self.cookie_storage.set_global_header(name, val)
        self._refresh_headers_display()
        self.notify(f"Injected Header: {name}")

    def action_clear_global_headers(self):
        self.cookie_storage.global_headers.clear()
        self._refresh_headers_display()
        self.notify("Cleared global headers")

    def _refresh_headers_display(self):
        viewer = self.query_one("#txt-global-headers", TextArea)
        if not self.cookie_storage.global_headers:
            viewer.text = "No active global headers."
        else:
            lines = [f"{k}: {v}" for k, v in self.cookie_storage.global_headers.items()]
            viewer.text = "Active Global Request Headers (Auto-Injected):\n" + "\n".join(lines)

    # ---------------------------------------------------------
    # JS Console & Deobfuscator Actions
    # ---------------------------------------------------------
    async def action_run_js(self):
        code = self.query_one("#txt-js-input", TextArea).text.strip()
        if not code:
            self.notify("Enter JavaScript code to execute", severity="warning")
            return

        target_url = self.query_one("#target-url", Input).value.strip()
        cookies_str = "; ".join([f"{k}={v}" for k, v in self.cookie_storage.cookies.items()])

        out_area = self.query_one("#txt-js-output", TextArea)
        self.notify("Executing JavaScript in sandbox...", timeout=1)

        logs, return_val, is_err = await self.js_engine.eval_js(code, url=target_url, cookies=cookies_str)

        text_to_scan = f"{logs}\n{return_val or ''}"
        flags = self.flag_tracker.scan(text_to_scan)
        if flags:
            self.update_flag_display()

        timestamp = "LIVE"
        snippet = code.splitlines()[0][:50] if code.splitlines() else code[:50]
        header = f"\n─── [JS Eval] : {snippet} ───\n"

        parts = [header]
        if flags:
            parts.append(f"🚩 FLAG DETECTED: {', '.join(flags)}\n")
        if logs:
            parts.append(f"[Console Logs]:\n{logs}\n")
        if return_val is not None:
            prefix = "[Error]: " if is_err else "=> "
            parts.append(f"{prefix}{return_val}\n")
        elif not logs:
            parts.append("=> undefined\n")

        out_area.text = out_area.text + "".join(parts)

    async def action_preload_target_scripts(self):
        if not self.discovered_assets:
            self.notify("No assets discovered yet. Click Analyze first.", severity="warning")
            return

        js_assets = [a for a in self.discovered_assets if a.get("type") == "SCRIPT" or a.get("url", "").endswith(".js")]
        if not js_assets:
            self.notify("No JavaScript files found on target.", severity="warning")
            return

        self.notify(f"Preloading {len(js_assets)} JavaScript file(s)...", timeout=2)
        loaded = 0
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for item in js_assets:
                url = item["url"]
                try:
                    r = await client.get(url)
                    if r.status_code == 200 and r.text:
                        self.js_engine.add_preloaded_script(url, r.text)
                        loaded += 1
                except Exception:
                    pass

        lbl = self.query_one("#lbl-js-status", Label)
        lbl.update(f"Runtime: Node.js (Preloaded {loaded} target scripts)")
        out_area = self.query_one("#txt-js-output", TextArea)
        out_area.text = (
            out_area.text
            + f"\n[✓] Successfully preloaded {loaded} target script(s) into sandbox environment!\n"
            + f"    Target functions, variables, and arrays are now directly callable.\n"
        )
        self.notify(f"Preloaded {loaded} script(s) into JS Sandbox!")

    def action_deobfuscate_js(self):
        input_area = self.query_one("#txt-js-input", TextArea)
        code = input_area.text
        if not code.strip():
            self.notify("Input area is empty", severity="warning")
            return
        deobf = deobfuscate_javascript(code)
        input_area.text = deobf
        self.notify("Deobfuscated hex, unicode, and packed JS!")

    def action_clear_js_output(self):
        self.query_one("#txt-js-output", TextArea).text = ""
        self.notify("Console output cleared")

    # ---------------------------------------------------------
    # Network History & CSRF PoC Actions
    # ---------------------------------------------------------
    def refresh_network_table(self):
        try:
            tbl = self.query_one("#tbl-network", DataTable)
            tbl.clear()
            for entry in self.network_logger.entries:
                tbl.add_row(
                    str(entry.id),
                    entry.timestamp,
                    entry.method,
                    str(entry.status_code),
                    f"{entry.bytes_len} B",
                    f"{entry.elapsed_ms} ms",
                    entry.url
                )
        except Exception:
            pass

    def display_selected_network_entry(self, row_idx: int = -1):
        tbl = self.query_one("#tbl-network", DataTable)
        if row_idx < 0:
            row_idx = tbl.cursor_row
        if not (0 <= row_idx < len(self.network_logger.entries)):
            return
        entry = self.network_logger.entries[row_idx]
        self.selected_network_entry = entry

        lbl = self.query_one("#lbl-net-meta", Label)
        lbl.update(f"{entry.method} {entry.url} [{entry.status_code}] ({entry.bytes_len} B, {entry.elapsed_ms} ms)")

        req_headers_str = "\n".join([f"{k}: {v}" for k, v in entry.req_headers.items()])
        req_text = f"=== REQUEST HEADERS ===\n{req_headers_str}\n\n=== REQUEST BODY ===\n{entry.req_body}" if entry.req_body else f"=== REQUEST HEADERS ===\n{req_headers_str}"
        self.query_one("#txt-net-req", TextArea).text = req_text

        resp_headers_str = "\n".join([f"{k}: {v}" for k, v in entry.resp_headers.items()])
        resp_text = f"=== RESPONSE HEADERS ===\n{resp_headers_str}\n\n=== RESPONSE BODY ===\n{entry.resp_body}"
        self.query_one("#txt-net-resp", TextArea).text = resp_text

    def action_clear_network_history(self):
        self.network_logger.clear()
        self.query_one("#tbl-network", DataTable).clear()
        self.query_one("#txt-net-req", TextArea).text = ""
        self.query_one("#txt-net-resp", TextArea).text = ""
        self.notify("Network history cleared")

    def action_send_network_to_repeater(self):
        if not self.selected_network_entry:
            tbl = self.query_one("#tbl-network", DataTable)
            if 0 <= tbl.cursor_row < len(self.network_logger.entries):
                self.selected_network_entry = self.network_logger.entries[tbl.cursor_row]
        if not self.selected_network_entry:
            self.notify("Select a network row first", severity="warning")
            return
        entry = self.selected_network_entry
        self.query_one("#rep-url", Input).value = entry.url
        self.query_one("#rep-method", Input).value = entry.method
        hdrs = "\n".join([f"{k}: {v}" for k, v in entry.req_headers.items()])
        self.query_one("#rep-headers", TextArea).text = hdrs
        self.query_one("#rep-body", TextArea).text = entry.req_body
        self.query_one(TabbedContent).active = "tab-repeater"
        self.notify(f"Sent {entry.method} {entry.url} to Repeater!")

    def action_copy_network_curl(self):
        if not self.selected_network_entry:
            self.notify("Select a network request first", severity="warning")
            return
        e = self.selected_network_entry
        cmd_parts = [f"curl -X {e.method} '{e.url}'"]
        for k, v in e.req_headers.items():
            cmd_parts.append(f"-H '{k}: {v}'")
        if e.req_body:
            cmd_parts.append(f"--data '{e.req_body}'")
        cmd = " ".join(cmd_parts)
        try:
            import shutil, subprocess
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=cmd.encode(), check=False)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=cmd.encode(), check=False)
        except Exception:
            pass
        self.notify(f"Copied cURL command: {cmd[:60]}...")

    def action_generate_network_csrf(self):
        if not self.selected_network_entry:
            self.notify("Select a network request first", severity="warning")
            return
        e = self.selected_network_entry
        params = {}
        if e.req_body:
            for pair in e.req_body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
        poc = generate_csrf_poc(e.method, e.url, params)
        self.query_one("#txt-net-resp", TextArea).text = poc
        self.notify("Generated CSRF PoC in Response Inspector!")

    def action_generate_form_csrf(self):
        forms_text = self.query_one("#txt-forms", TextArea).text
        target_url = self.query_one("#target-url", Input).value.strip()
        form_action = target_url
        form_method = "POST"
        fields = {}
        for line in forms_text.splitlines():
            if "Action:" in line:
                act = line.split("Action:", 1)[1].split(",")[0].strip().strip("'\"")
                if act:
                    form_action = urllib.parse.urljoin(target_url, act)
            elif "Method:" in line:
                mth = line.split("Method:", 1)[1].strip().strip("'\"")
                if mth:
                    form_method = mth
            elif "•" in line and "=" in line:
                m = re.search(r"•\s*([a-zA-Z0-9_\-]+).*?=\s*'([^']*)'", line)
                if m:
                    fields[m.group(1)] = m.group(2) or "test_payload"
        poc = generate_csrf_poc(form_method, form_action, fields)
        self.query_one("#txt-forms", TextArea).text = (
            "=== GENERATED CSRF EXPLOIT POC ===\n\n" + poc + "\n\n=== DISCOVERED FORMS ===\n\n" + forms_text
        )
        self.notify("Generated CSRF PoC in Forms pane!")

    def action_generate_repeater_csrf(self):
        url = self.query_one("#rep-url", Input).value.strip()
        method = self.query_one("#rep-method", Input).value.strip()
        body = self.query_one("#rep-body", TextArea).text.strip()
        fields = {}
        if body:
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    fields[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
        poc = generate_csrf_poc(method, url, fields)
        self.query_one("#rep-resp-body", TextArea).text = poc
        self.notify("Generated CSRF PoC in Response Body!")

    # ---------------------------------------------------------
    # Elements (HTML DOM Tree) Actions
    # ---------------------------------------------------------
    def action_refresh_dom_tree(self):
        if not self.current_html:
            return
        try:
            tree = self.query_one("#tree-dom", Tree)
            query = self.query_one("#inp-dom-search", Input).value.strip()
            build_dom_tree(
                tree=tree,
                html=self.current_html,
                search_query=query,
                hidden_only=self.dom_hidden_only,
                flag_tracker=self.flag_tracker
            )
        except Exception:
            pass

    def action_search_dom_tree(self):
        self.action_refresh_dom_tree()
        query = self.query_one("#inp-dom-search", Input).value.strip()
        if query:
            self.notify(f"Filtered DOM tree by: '{query}'")
        else:
            self.notify("Showing full DOM tree")

    def action_toggle_hidden_dom(self):
        self.dom_hidden_only = not self.dom_hidden_only
        btn = self.query_one("#btn-dom-hidden", Button)
        if self.dom_hidden_only:
            btn.label = "🔒 Hidden: ON"
            btn.variant = "warning"
            self.notify("Showing ONLY hidden DOM elements", severity="warning")
        else:
            btn.label = "🔒 Hidden Only"
            btn.variant = "default"
            self.notify("Showing full DOM tree")
        self.action_refresh_dom_tree()

    def display_selected_dom_node(self, node: TreeNode):
        data = node.data
        if data is None:
            return
        try:
            attrs_viewer = self.query_one("#txt-node-attrs", TextArea)
            html_viewer = self.query_one("#txt-node-html", TextArea)

            if hasattr(data, "name"):  # Tag
                self.selected_dom_tag = data
                attrs_viewer.text = format_tag_details(data)
                try:
                    html_viewer.text = data.prettify()
                except Exception:
                    html_viewer.text = str(data)
                
                flags = self.flag_tracker.scan(str(data))
                if flags:
                    self.update_flag_display()
            else:  # Text node
                self.selected_dom_tag = None
                text_val = str(data)
                attrs_viewer.text = f"=== TEXT NODE ===\nLength: {len(text_val)} chars"
                html_viewer.text = text_val
                flags = self.flag_tracker.scan(text_val)
                if flags:
                    self.update_flag_display()
        except Exception:
            pass

    def action_copy_dom_outer_html(self):
        if not self.selected_dom_tag:
            self.notify("Select an HTML element first", severity="warning")
            return
        try:
            outer = self.selected_dom_tag.prettify()
        except Exception:
            outer = str(self.selected_dom_tag)
        try:
            import shutil, subprocess
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=outer.encode(), check=False)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=outer.encode(), check=False)
        except Exception:
            pass
        self.notify(f"Copied <{self.selected_dom_tag.name}> outer HTML to clipboard!")

    # ---------------------------------------------------------
    # cURL Workbench Actions
    # ---------------------------------------------------------
    def load_selected_curl_template(self, row_idx: int):
        if not (0 <= row_idx < len(CURL_TEMPLATES)):
            return
        tpl = CURL_TEMPLATES[row_idx]
        target_url = self.query_one("#target-url", Input).value.strip() or self.initial_url
        rendered = render_curl_template(tpl["cmd"], target_url, self.cookie_storage.cookies)
        self.query_one("#txt-curl-cmd", TextArea).text = rendered
        self.notify(f"Loaded template: {tpl['name']}")

    async def action_exec_curl(self):
        cmd = self.query_one("#txt-curl-cmd", TextArea).text.strip()
        if not cmd:
            self.notify("Enter a curl command to execute", severity="warning")
            return
        if not cmd.startswith("curl"):
            self.notify("Command must start with 'curl'", severity="warning")
            return

        self.notify("Executing cURL command...", timeout=1)
        stdout, stderr, elapsed_ms, code = await execute_curl_command(cmd, timeout=15)

        # Log to network history if it has URL
        parsed = parse_curl_to_repeater(cmd)
        if parsed["url"]:
            self.network_logger.log(
                method=parsed["method"],
                url=parsed["url"],
                status_code=code,
                bytes_len=len(stdout.encode()),
                elapsed_ms=round(elapsed_ms, 1),
                req_headers=parsed["headers"],
                req_body=parsed["body"],
                resp_headers={},
                resp_body=stdout[:1000]
            )
            self.refresh_network_table()

        # Update meta label
        status_text = f"Exit Code: {code} | Latency: {elapsed_ms:.1f}ms | Output Size: {len(stdout)} bytes"
        self.query_one("#lbl-curl-meta", Label).update(status_text)

        # Scan for flags in output
        flags = self.flag_tracker.scan(stdout + "\n" + stderr)
        if flags:
            self.update_flag_display()
            self.notify(f"🚩 FLAG DETECTED IN CURL OUTPUT: {', '.join(flags)}", timeout=5)

        # Format output
        output_parts = []
        if flags:
            output_parts.append(f"🚩 CAPTURED FLAG(S): {', '.join(flags)}\n\n")
        if stdout:
            output_parts.append(stdout)
        if stderr and ("error" in stderr.lower() or "failed" in stderr.lower() or code != 0):
            output_parts.append(f"\n[STDERR / Details]:\n{stderr}")
        elif not stdout and not stderr:
            output_parts.append("(Command completed with empty output)")

        self.query_one("#txt-curl-resp", TextArea).text = "".join(output_parts)

    def action_curl_to_repeater(self):
        cmd = self.query_one("#txt-curl-cmd", TextArea).text.strip()
        if not cmd:
            self.notify("cURL command is empty", severity="warning")
            return
        parsed = parse_curl_to_repeater(cmd)
        if not parsed["url"]:
            self.notify("Could not parse target URL from curl command", severity="warning")
            return
        self.query_one("#rep-url", Input).value = parsed["url"]
        self.query_one("#rep-method", Input).value = parsed["method"]
        hdrs_str = "\n".join([f"{k}: {v}" for k, v in parsed["headers"].items()])
        self.query_one("#rep-headers", TextArea).text = hdrs_str
        self.query_one("#rep-body", TextArea).text = parsed["body"]
        self.query_one(TabbedContent).active = "tab-repeater"
        self.notify("Sent parsed cURL request to Repeater!")

    def action_curl_to_python(self):
        cmd = self.query_one("#txt-curl-cmd", TextArea).text.strip()
        if not cmd:
            self.notify("cURL command is empty", severity="warning")
            return
        py_script = curl_to_python_script(cmd)
        self.query_one("#txt-curl-resp", TextArea).text = (
            "=== GENERATED PYTHON HTTPX SCRIPT ===\n\n" + py_script
        )
        self.notify("Generated Python script in Response pane!")

    def action_copy_curl_command(self):
        cmd = self.query_one("#txt-curl-cmd", TextArea).text.strip()
        if not cmd:
            return
        try:
            import shutil, subprocess
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=cmd.encode(), check=False)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=cmd.encode(), check=False)
        except Exception:
            pass
        self.notify("Copied cURL command to clipboard!")

    def action_copy_curl_response(self):
        resp = self.query_one("#txt-curl-resp", TextArea).text
        if not resp:
            return
        try:
            import shutil, subprocess
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=resp.encode(), check=False)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=resp.encode(), check=False)
        except Exception:
            pass
        self.notify("Copied output to clipboard!")

    def action_scan_curl_flags(self):
        resp = self.query_one("#txt-curl-resp", TextArea).text
        flags = self.flag_tracker.scan(resp)
        if flags:
            self.update_flag_display()
            self.notify(f"Found flag(s): {', '.join(flags)}")
        else:
            self.notify("No flags detected in current output")

    # ---------------------------------------------------------
    # SQLi Workbench Actions
    # ---------------------------------------------------------
    def _select_dbms(self, dbms: str):
        self.selected_dbms = dbms
        self._populate_sqli_table(dbms)
        self._update_sqli_info()
        self.notify(f"Switched SQLi DBMS: {dbms}")

    def _update_sqli_info(self):
        lbl = self.query_one("#lbl-sqli-info", Label)
        lbl.update(f"Active DBMS: {self.selected_dbms} | Column Fuzz: {self.sqli_column_count}")

    def load_selected_sqli_template(self, row_idx: int):
        if not (0 <= row_idx < len(self.active_sqli_templates)):
            return
        item = self.active_sqli_templates[row_idx]
        self.query_one("#txt-sqli-editor", TextArea).text = item["payload"]
        self.notify(f"Loaded {item['name']}")

    def _tamper_active_sqli(self, tamper_func, name: str):
        editor = self.query_one("#txt-sqli-editor", TextArea)
        raw = editor.text.strip()
        if not raw:
            return
        tampered = tamper_func(raw)
        editor.text = tampered
        self.notify(f"Applied WAF Tamper: {name}")

    def action_sqli_to_repeater(self):
        payload = self.query_one("#txt-sqli-editor", TextArea).text.strip()
        if not payload:
            return
        rep_url = self.query_one("#rep-url", Input).value
        if "?" in rep_url:
            base, qs = rep_url.split("?", 1)
            new_url = f"{base}?id={urllib.parse.quote(payload)}"
        else:
            new_url = f"{rep_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
        self.query_one("#rep-url", Input).value = new_url
        self.query_one(TabbedContent).active = "tab-repeater"
        self.notify("Injected SQL payload into Repeater URL!")

    def action_sqli_to_curl(self):
        payload = self.query_one("#txt-sqli-editor", TextArea).text.strip()
        if not payload:
            return
        target = self.query_one("#target-url", Input).value.strip() or self.initial_url
        cmd = f'curl -i -k -G "{target.rstrip("/")}/" --data-urlencode "id={payload}"'
        self.query_one("#txt-curl-cmd", TextArea).text = cmd
        self.query_one(TabbedContent).active = "tab-curl"
        self.notify("Sent SQL payload to cURL Workshop!")

    def action_copy_sqli_payload(self):
        payload = self.query_one("#txt-sqli-editor", TextArea).text.strip()
        self._copy_to_system_clipboard(payload)
        self.notify("Copied SQL payload to clipboard!")

    # ---------------------------------------------------------
    # PHP Sandbox Actions
    # ---------------------------------------------------------
    async def action_exec_php(self):
        code = self.query_one("#txt-php-editor", TextArea).text.strip()
        if not code:
            self.notify("PHP editor is empty", severity="warning")
            return
        self.notify("Executing PHP script...", timeout=1)
        lbl = self.query_one("#lbl-php-meta", Label)
        lbl.update("PHP Status: Running...")
        
        stdout, stderr, elapsed_ms, code_ret = await execute_php_script(code, timeout=10)
        lbl.update(f"PHP Status: Exit {code_ret} | Latency: {elapsed_ms:.1f}ms")
        
        output = stdout if stdout else ""
        if stderr:
            output += f"\n[PHP STDERR]:\n{stderr}"
        if not output:
            output = "(Script executed with no output)"

        flags = self.flag_tracker.scan(output)
        if flags:
            self.update_flag_display()
            self.notify(f"🚩 FLAG IN PHP OUTPUT: {', '.join(flags)}", severity="warning", timeout=5)

        self.query_one("#txt-php-output", TextArea).text = output

    def load_selected_php_wrapper(self, row_idx: int):
        if not (0 <= row_idx < len(PHP_LFI_WRAPPERS)):
            return
        item = PHP_LFI_WRAPPERS[row_idx]
        self._copy_to_system_clipboard(item["wrapper"])
        self.notify(f"Copied wrapper to clipboard: {item['name']}")

    def load_selected_php_hash(self, row_idx: int):
        if not (0 <= row_idx < len(PHP_MAGIC_HASHES)):
            return
        item = PHP_MAGIC_HASHES[row_idx]
        self._copy_to_system_clipboard(item["input"])
        self.notify(f"Copied magic input: '{item['input']}' (Hash: {item['hash'][:16]}...)")

    def action_php_to_repeater(self):
        code = self.query_one("#txt-php-editor", TextArea).text.strip()
        if not code:
            return
        self.query_one("#rep-body", TextArea).text = code
        self.query_one("#rep-method", Input).value = "POST"
        self.query_one(TabbedContent).active = "tab-repeater"
        self.notify("Sent PHP script to Repeater POST body!")

    def action_copy_php_code(self):
        code = self.query_one("#txt-php-editor", TextArea).text.strip()
        self._copy_to_system_clipboard(code)
        self.notify("Copied PHP code to clipboard!")

    # ---------------------------------------------------------
    # Payload Vault Actions
    # ---------------------------------------------------------
    def action_search_payload_vault(self):
        query = self.query_one("#inp-payload-search", Input).value.strip()
        self._populate_payloads_table(query)

    def load_selected_payload_item(self, row_idx: int):
        if not (0 <= row_idx < len(self.active_payload_list)):
            return
        item = self.active_payload_list[row_idx]
        self.query_one("#txt-payload-view", TextArea).text = item["payload"]
        self.query_one("#txt-payload-notes", TextArea).text = (
            f"Category: {item['category']}\n"
            f"Type: {item['type']}\n"
            f"Name: {item['name']}\n"
            f"Description: {item['desc']}"
        )

    def action_payload_to_repeater(self):
        payload = self.query_one("#txt-payload-view", TextArea).text.strip()
        if not payload:
            return
        self.query_one("#rep-body", TextArea).text = payload
        self.query_one(TabbedContent).active = "tab-repeater"
        self.notify("Sent payload to Repeater!")

    def action_payload_to_curl(self):
        payload = self.query_one("#txt-payload-view", TextArea).text.strip()
        if not payload:
            return
        target = self.query_one("#target-url", Input).value.strip() or self.initial_url
        cmd = f'curl -i -k -X POST "{target.rstrip("/")}/" -d "{payload}"'
        self.query_one("#txt-curl-cmd", TextArea).text = cmd
        self.query_one(TabbedContent).active = "tab-curl"
        self.notify("Sent payload to cURL Workshop!")

    def action_copy_payload_string(self):
        payload = self.query_one("#txt-payload-view", TextArea).text.strip()
        self._copy_to_system_clipboard(payload)
        self.notify("Copied payload string to clipboard!")

    def _copy_to_system_clipboard(self, text: str):
        if not text:
            return
        try:
            import shutil, subprocess
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=False)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=text.encode(), check=False)
            elif shutil.which("clip"):
                subprocess.run(["clip"], input=text.encode(), check=False)
        except Exception:
            pass



