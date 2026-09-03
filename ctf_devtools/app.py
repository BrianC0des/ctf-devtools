from __future__ import annotations
"""Main Textual TUI Application for CTF DevTools with universal text & clean 2-tier workspace navigation."""
import asyncio
import json
import os
import pathlib
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

from . import __version__
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
    background: transparent;
    border-bottom: solid #3b4261;
    align: left middle;
}

#ws-bar {
    height: 3;
    padding: 0 1;
    background: transparent;
    border-bottom: solid #24283b;
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
    width: 38;
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
    width: auto;
    min-width: 11;
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
    width: auto;
    min-width: 11;
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
    width: auto;
    min-width: 9;
    margin: 0 1;
    padding: 0 1;
}

.btn-secondary:hover {
    background: #414868;
    color: #ffffff;
    text-style: bold;
}

.btn-ws {
    background: #1f2335;
    color: #565f89;
    text-style: bold;
    border: none;
    height: 1;
    width: auto;
    min-width: 14;
    margin-right: 1;
    padding: 0 1;
}

.btn-ws:hover {
    background: #24283b;
    color: #bb9af7;
}

.btn-ws-active {
    background: #7aa2f7;
    color: #11121d;
    text-style: bold;
    border: none;
    height: 1;
    width: auto;
    min-width: 14;
    margin-right: 1;
    padding: 0 1;
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
    height: 1;
    background: #1f2335;
    border: none;
    padding: 0 1;
    margin-left: 1;
}

TabbedContent {
    height: 1fr;
    background: transparent;
}

TabPane {
    padding: 1 1;
    background: transparent;
}

/* Sub-tabs inside each workspace */
TabbedContent > Tabs {
    height: 2;
    background: transparent;
    border-bottom: solid #24283b;
}

TabbedContent > Tabs > Tab {
    height: 2;
    background: transparent;
    color: #565f89;
    text-style: bold;
    padding: 0 2;
    border: none;
}

TabbedContent > Tabs > Tab:hover {
    color: #bb9af7;
    background: #1f2335;
}

TabbedContent > Tabs > Tab.-active {
    color: #7aa2f7;
    background: #24283b;
    text-style: bold;
    border-bottom: tall #7aa2f7;
}

.card-panel {
    border: round #3b4261;
    background: transparent;
    padding: 1 1;
    margin: 0 1;
    height: 1fr;
}

.card-title {
    text-style: bold;
    color: #7aa2f7;
    margin-bottom: 1;
}

.sub-bar {
    height: 3;
    align: left middle;
    margin-bottom: 1;
}

.sub-bar Input {
    width: 28;
    height: 1;
    border: none;
    background: #24283b;
    color: #ffffff;
    margin-right: 1;
}

.pane-half {
    width: 1fr;
    height: 1fr;
}

.h-short {
    height: 8;
}

.status-alert {
    color: #ff9e64;
    text-style: italic;
    margin-left: 1;
}

.status-meta {
    color: #7dcfff;
    text-style: italic;
    margin-bottom: 1;
}

DataTable {
    background: #16161e 90%;
    border: none;
    height: 1fr;
    margin-bottom: 1;
}

DataTable > .datatable--header {
    background: #24283b;
    color: #7aa2f7;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #3d59a1;
    color: #ffffff;
    text-style: bold;
}

Tree {
    background: #16161e 90%;
    border: none;
    height: 1fr;
    color: #c0caf5;
    padding: 1;
}

Tree:focus {
    border: none;
}

Tree > .tree--cursor {
    background: #3d59a1;
    color: #ffffff;
    text-style: bold;
}

TextArea {
    background: #16161e 95%;
    color: #c0caf5;
    border: none;
    height: 1fr;
}

TextArea:focus {
    border: none;
    background: #16161e;
}
"""

WORKSPACES = [
    ("tab-inspector", "btn-ws-1", "1: INSPECTOR"),
    ("tab-network", "btn-ws-2", "2: NETWORK"),
    ("tab-repeater", "btn-ws-3", "3: REPEATER"),
    ("tab-exploit", "btn-ws-4", "4: EXPLOIT"),
    ("tab-scripting", "btn-ws-5", "5: SCRIPT"),
    ("tab-decoders", "btn-ws-6", "6: DECODE"),
]

class CTFDevToolsApp(App):
    """Modern Offensive Web CTF DevTools Terminal Workstation."""

    TITLE = f"CTF DevTools v{__version__}"
    SUB_TITLE = "Terminal Offensive Workstation"
    CSS = APP_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("1", "jump_workspace('tab-inspector')", "[1] Inspect", show=True),
        Binding("2", "jump_workspace('tab-network')", "[2] Network", show=True),
        Binding("3", "jump_workspace('tab-repeater')", "[3] Repeat", show=True),
        Binding("4", "jump_workspace('tab-exploit')", "[4] Exploit", show=True),
        Binding("5", "jump_workspace('tab-scripting')", "[5] Script", show=True),
        Binding("6", "jump_workspace('tab-decoders')", "[6] Decode", show=True),
        Binding("ctrl+a", "analyze_target", "Analyze", show=True),
        Binding("ctrl+s", "send_repeater", "Send", show=True),
        Binding("ctrl+r", "run_scanner", "Recon", show=True),
        Binding("ctrl+e", "exec_curl", "cURL", show=True),
        Binding("ctrl+b", "exec_php", "PHP", show=True),
        Binding("ctrl+j", "run_js", "JS", show=True),
    ]

    def __init__(self, initial_url: str = "http://127.0.0.1:8000"):
        super().__init__()
        init_platform()
        self.initial_url = initial_url
        self.active_workspace_id = "tab-inspector" if initial_url else "tab-repeater"
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
            yield Button("Analyze", id="btn-analyze", classes="btn-primary")
            yield Button("Recon", id="btn-recon-top", classes="btn-accent")
            yield Label("FLAG: 0", id="lbl-flags", classes="flag-badge")
            yield Input(value="challenge_1", placeholder="Session", id="inp-session")
            yield Button("Save", id="btn-save-session", classes="btn-secondary")

        with Horizontal(id="ws-bar"):
            for ws_id, btn_id, label in WORKSPACES:
                cls = "btn-ws-active" if ws_id == self.active_workspace_id else "btn-ws"
                yield Button(label, id=btn_id, classes=cls)

        with TabbedContent(initial=self.active_workspace_id, id="root-tabs"):
            # =========================================================
            # WORKSPACE 1: INSPECTOR (DOM Tree, Recon, Sources, Comments)
            # =========================================================
            with TabPane("1. INSPECTOR", id="tab-inspector"):
                with TabbedContent(initial="subtab-dom"):
                    # SUBTAB 1.1: DOM Tree
                    with TabPane("DOM Elements", id="subtab-dom"):
                        with Vertical(classes="card-panel"):
                            with Horizontal(classes="sub-bar"):
                                yield Input(placeholder="Filter tag, id, class, or text (e.g. input, #secret, hidden)", id="inp-dom-search")
                                yield Button("Filter", id="btn-dom-search", classes="btn-primary")
                                yield Button("Hidden Only", id="btn-dom-hidden", classes="btn-secondary")
                                yield Button("Copy HTML", id="btn-dom-copy", classes="btn-secondary")
                                yield Button("Re-Parse", id="btn-dom-refresh", classes="btn-accent")
                            with Horizontal():
                                with Vertical(classes="pane-half"):
                                    yield Label("HTML DOM Tree (Click/Arrow to Inspect)", classes="card-title")
                                    yield Tree("Document (Empty)", id="tree-dom")
                                with Vertical(classes="pane-half"):
                                    yield Label("Selected Element Attributes & Flags:", classes="card-title")
                                    yield TextArea(id="txt-node-attrs", read_only=True, classes="h-short")
                                    yield Label("Element Outer HTML Snippet:", classes="card-title")
                                    yield TextArea(id="txt-node-html", read_only=True)

                    # SUBTAB 1.2: Recon Probes
                    with TabPane("Recon Probes", id="subtab-recon"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Sensitive Paths & Sensitive Probes", classes="card-title")
                                yield DataTable(id="tbl-recon")
                                yield Label("Server Tech Stack & Disclosed Headers", classes="card-title")
                                yield TextArea(id="txt-tech-stack", read_only=True, classes="h-short")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Probe File Content Inspector", classes="card-title")
                                yield Label("Selected File: None", id="lbl-probe-file", classes="status-meta")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Fetch Full", id="btn-fetch-probe", classes="btn-primary")
                                    yield Button("To Repeater", id="btn-probe-rep", classes="btn-secondary")
                                    yield Button("cURL", id="btn-probe-curl", classes="btn-secondary")
                                    yield Button("Scan Secrets", id="btn-scan-probe", classes="btn-accent")
                                yield TextArea(id="txt-probe-content", read_only=True)

                    # SUBTAB 1.3: Sources & Loaded Files
                    with TabPane("Sources & Files", id="subtab-sources"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Loaded Assets & Discovered Files", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Fetch / View", id="btn-fetch-asset", classes="btn-primary")
                                    yield Button("Download", id="btn-download-asset", classes="btn-accent")
                                    yield Button("Scan Secrets", id="btn-scan-asset", classes="btn-secondary")
                                    yield Button("Probe .map", id="btn-probe-map", classes="btn-secondary")
                                yield DataTable(id="tbl-assets")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("File Inspector", id="lbl-asset-info", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("cURL", id="btn-asset-curl", classes="btn-secondary")
                                    yield Button("To Repeater", id="btn-asset-rep", classes="btn-secondary")
                                yield TextArea(id="txt-asset-content", read_only=True)

                    # SUBTAB 1.4: Comments & Secrets
                    with TabPane("Comments & Secrets", id="subtab-comments"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Harvested HTML & JS Comments", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Refresh Comments", id="btn-gather-comments", classes="btn-primary")
                                    yield Button("Scan Secrets", id="btn-scan-comments", classes="btn-accent")
                                yield TextArea(id="txt-comments", read_only=True)
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Discovered Forms & Hidden Inputs", classes="card-title")
                                yield TextArea(id="txt-forms", read_only=True)

            # =========================================================
            # WORKSPACE 2: NETWORK (Traffic, Cookies, Spider, WebSockets)
            # =========================================================
            with TabPane("2. NETWORK", id="tab-network"):
                with TabbedContent(initial="subtab-netlog"):
                    # SUBTAB 2.1: Traffic Log
                    with TabPane("Traffic History", id="subtab-netlog"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("HTTP/S Traffic History", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Replay in Repeater", id="btn-net-replay", classes="btn-primary")
                                    yield Button("Export cURL", id="btn-net-curl", classes="btn-secondary")
                                    yield Button("CSRF PoC", id="btn-net-csrf", classes="btn-accent")
                                    yield Button("Clear History", id="btn-net-clear", classes="btn-secondary")
                                yield DataTable(id="tbl-network")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Request & Response Inspector", classes="card-title")
                                yield TextArea(id="txt-net-details", read_only=True)

                    # SUBTAB 2.2: Storage & Cookies
                    with TabPane("Storage & Cookies", id="subtab-storage"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Active Cookie Jar", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Input(placeholder="Cookie Name", id="inp-cookie-name")
                                    yield Input(placeholder="Value", id="inp-cookie-val")
                                    yield Button("+ Set", id="btn-set-cookie", classes="btn-primary")
                                    yield Button("Delete", id="btn-del-cookie", classes="btn-secondary")
                                    yield Button("Decode", id="btn-decode-cookie", classes="btn-accent")
                                yield DataTable(id="tbl-cookies")
                                yield Label("Decoded Cookie Value (JWT / Flask / Base64):", classes="card-title")
                                yield TextArea(id="txt-cookie-decoded", read_only=True)
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Global Auth Headers", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Input(value="Authorization", placeholder="Header Name", id="inp-hdr-name")
                                    yield Input(placeholder="Bearer token", id="inp-hdr-val")
                                    yield Button("+ Set Header", id="btn-set-hdr", classes="btn-primary")
                                    yield Button("Clear", id="btn-del-hdr", classes="btn-secondary")
                                yield TextArea(id="txt-global-headers", read_only=True)
                                yield Label("Client-Side Storage (localStorage / sessionStorage):", classes="card-title")
                                yield DataTable(id="tbl-storage")

                    # SUBTAB 2.3: Site Crawler
                    with TabPane("Site Crawler", id="subtab-crawler"):
                        with Horizontal(classes="sub-bar"):
                            yield Button("Start Spider", id="btn-spider", classes="btn-primary")
                            yield Label("Recursively maps internal routes and extracts JavaScript endpoints", classes="status-alert")
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Crawled Routes", classes="card-title")
                                yield DataTable(id="tbl-crawled")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Discovered API Endpoints", classes="card-title")
                                yield TextArea(id="txt-js-routes", read_only=True)

                    # SUBTAB 2.4: WebSockets
                    with TabPane("WebSockets", id="subtab-ws"):
                        with Vertical(classes="card-panel"):
                            yield Label("WebSocket Stream", classes="card-title")
                            with Horizontal(classes="sub-bar"):
                                yield Input(value="ws://127.0.0.1:8000/ws", id="ws-url")
                                yield Button("Connect", id="btn-ws-connect", classes="btn-primary")
                                yield Button("Disconnect", id="btn-ws-disconnect", classes="btn-secondary")
                            yield Label("Live Frames:")
                            yield TextArea(id="txt-ws-log", read_only=True)
                            yield Label("Send Frame:")
                            with Horizontal(classes="sub-bar"):
                                yield Input(value='{"action": "ping"}', id="ws-payload")
                                yield Button("Send", id="btn-ws-send", classes="btn-primary")

            # =========================================================
            # WORKSPACE 3: REPEATER & CURL STUDIO
            # =========================================================
            with TabPane("3. REPEATER", id="tab-repeater"):
                with TabbedContent(initial="subtab-repeater"):
                    # SUBTAB 3.1: HTTP Composer
                    with TabPane("Request Composer", id="subtab-repeater"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Request Composer (Supports FUZZ marker)", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Input(value="GET", id="rep-method", placeholder="Method")
                                    yield Input(value=self.initial_url, id="rep-url", placeholder="URL")
                                yield Label("Headers:")
                                yield TextArea("User-Agent: CTF-DevTools/1.0\nAccept: */*\n", id="rep-headers")
                                yield Label("Body:")
                                yield TextArea("", id="rep-body")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Send (Ctrl+S)", id="btn-rep-send", classes="btn-primary")
                                    yield Button("cURL", id="btn-rep-curl", classes="btn-secondary")
                                    yield Button("Python", id="btn-rep-python", classes="btn-secondary")
                                    yield Button("Fuzz (100)", id="btn-rep-fuzz", classes="btn-accent")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Server Response", classes="card-title")
                                yield Label("Status: Ready | Time: -- ms | Length: --", id="lbl-rep-status", classes="status-meta")
                                yield TextArea(id="rep-response", read_only=True)

                    # SUBTAB 3.2: cURL Studio
                    with TabPane("cURL Studio", id="subtab-curl"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("cURL Command Studio", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Execute (Ctrl+E)", id="btn-curl-exec", classes="btn-primary")
                                    yield Button("Format", id="btn-curl-fmt", classes="btn-secondary")
                                    yield Button("To Repeater", id="btn-curl-to-rep", classes="btn-secondary")
                                    yield Button("To Python", id="btn-curl-to-py", classes="btn-secondary")
                                    yield Button("Clear", id="btn-curl-clear", classes="btn-secondary")
                                yield TextArea(f'curl -i -k "{self.initial_url}"', id="txt-curl-cmd")
                                with Horizontal(classes="sub-bar"):
                                    yield Label("CTF Bypass Templates:", classes="card-title")
                                    yield Button("Load Template", id="btn-curl-load-tpl", classes="btn-accent")
                                yield DataTable(id="tbl-curl-templates")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Response & Execution Output", classes="card-title")
                                yield Label("Status: Ready | Latency: -- ms | Code: --", id="lbl-curl-meta", classes="status-meta")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Copy Command", id="btn-curl-copy-cmd", classes="btn-secondary")
                                    yield Button("Copy Output", id="btn-curl-copy-resp", classes="btn-secondary")
                                    yield Button("Scan Flags", id="btn-curl-scan-flags", classes="btn-accent")
                                yield TextArea(id="txt-curl-resp", read_only=True)

            # =========================================================
            # WORKSPACE 4: EXPLOIT HUB (SQLi, PHP Sandbox, Payload Vault)
            # =========================================================
            with TabPane("4. EXPLOIT HUB", id="tab-exploit"):
                with TabbedContent(initial="subtab-sqli"):
                    # SUBTAB 4.1: SQL Injection
                    with TabPane("SQL Injection", id="subtab-sqli"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("SQLi Dialect & Attack Templates", classes="card-title")
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
                                    yield Button("UNION Probe", id="btn-sqli-gen-union", classes="btn-primary")
                                    yield Button("ORDER BY", id="btn-sqli-gen-orderby", classes="btn-accent")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("SQL Payload & WAF Bypass Tamper", classes="card-title")
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
                                    yield Button("To Repeater", id="btn-sqli-to-rep", classes="btn-primary")
                                    yield Button("cURL", id="btn-sqli-to-curl", classes="btn-secondary")
                                    yield Button("Copy Payload", id="btn-sqli-copy", classes="btn-accent")

                    # SUBTAB 4.2: PHP Sandbox
                    with TabPane("PHP Sandbox", id="subtab-php"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Interactive PHP Script Sandbox", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Run PHP (Ctrl+B)", id="btn-php-run", classes="btn-primary")
                                    yield Button("To Repeater", id="btn-php-to-rep", classes="btn-secondary")
                                    yield Button("Clear", id="btn-php-clear", classes="btn-secondary")
                                    yield Button("Copy Code", id="btn-php-copy", classes="btn-accent")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("WebShell", id="btn-php-tpl-shell", classes="btn-secondary")
                                    yield Button("POP Chain", id="btn-php-tpl-pop", classes="btn-secondary")
                                    yield Button("0e Fuzzer", id="btn-php-tpl-hash", classes="btn-secondary")
                                    yield Button("Preload Bypass", id="btn-php-tpl-preload", classes="btn-secondary")
                                yield TextArea(PHP_STARTER_TEMPLATES["Web Shell / Command Execution"], id="txt-php-editor")
                                yield Label("Magic Hashes (0e... Loose Comparisons '=='):", classes="card-title")
                                yield DataTable(id="tbl-php-hashes")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Execution Output & Results", classes="card-title")
                                yield Label("PHP Status: Ready | Latency: -- ms", id="lbl-php-meta", classes="status-meta")
                                yield TextArea(id="txt-php-output", read_only=True)
                                yield Label("PHP LFI Wrappers & Filter Chains (Click to Load):", classes="card-title")
                                yield DataTable(id="tbl-php-wrappers")

                    # SUBTAB 4.3: Payload Vault
                    with TabPane("Payload Vault", id="subtab-payloads"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Universal CTF Payload Vault", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Input(placeholder="Search payloads (xss, ssti, shell, bypass, aws...)", id="inp-payload-search")
                                    yield Button("Search", id="btn-payload-search", classes="btn-primary")
                                    yield Button("Reset", id="btn-payload-reset", classes="btn-secondary")
                                yield DataTable(id="tbl-payloads")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Selected Payload String", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("To Repeater", id="btn-payload-to-rep", classes="btn-primary")
                                    yield Button("cURL", id="btn-payload-to-curl", classes="btn-secondary")
                                    yield Button("Copy String", id="btn-payload-copy", classes="btn-accent")
                                yield TextArea(id="txt-payload-view", read_only=False)
                                yield Label("Description & Exploitation Notes:", classes="card-title")
                                yield TextArea(id="txt-payload-notes", read_only=True, classes="h-short")

            # =========================================================
            # WORKSPACE 5: SCRIPTING & OOB (JS Console, Callbacks)
            # =========================================================
            with TabPane("5. SCRIPTING", id="tab-scripting"):
                with TabbedContent(initial="subtab-js"):
                    # SUBTAB 5.1: JS Console
                    with TabPane("JS Console", id="subtab-js"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Interactive JavaScript Editor", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Button("Run (Ctrl+J)", id="btn-js-run", classes="btn-primary")
                                    yield Button("Preload Scripts", id="btn-js-preload", classes="btn-secondary")
                                    yield Button("Deobfuscate", id="btn-js-deobf", classes="btn-secondary")
                                    yield Button("Clear", id="btn-js-clear", classes="btn-accent")
                                yield TextArea("// JS expressions or custom crypto solvers:\nconsole.log('Location:', location.href);\nconsole.log('Cookies:', document.cookie);\n", id="txt-js-input")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Execution Output & Console Logs", classes="card-title")
                                yield Label("Status: Ready | Time: -- ms", id="lbl-js-status", classes="status-meta")
                                yield TextArea(id="txt-js-output", read_only=True)

                    # SUBTAB 5.2: OOB Callbacks
                    with TabPane("OOB Callbacks", id="subtab-oob"):
                        with Horizontal():
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Local OOB HTTP Listener", classes="card-title")
                                with Horizontal(classes="sub-bar"):
                                    yield Input(value="9999", id="oob-port", placeholder="Port")
                                    yield Button("Start", id="btn-oob-start", classes="btn-primary")
                                    yield Button("Stop", id="btn-oob-stop", classes="btn-secondary")
                                yield Label("Incoming Requests:")
                                yield DataTable(id="tbl-oob")
                            with Vertical(classes="card-panel pane-half"):
                                yield Label("Captured Flags Archive", classes="card-title")
                                yield TextArea(id="txt-all-flags", read_only=True)

            # =========================================================
            # WORKSPACE 6: DECODERS (CyberChef-Lite)
            # =========================================================
            with TabPane("6. DECODERS", id="tab-decoders"):
                with Vertical(classes="card-panel"):
                    yield Label("Input Payload / Token / Hash:", classes="card-title")
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
                    yield Label("Decoded Output:", classes="card-title")
                    yield TextArea(id="dec-output", read_only=True)

        yield Footer()

    def on_mount(self) -> None:
        try:
            from textual.widgets._tabbed_content import ContentTabs
            self.query_one("#root-tabs", TabbedContent).get_child_by_type(ContentTabs).display = False
        except Exception:
            pass

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

    def action_jump_workspace(self, workspace_id: str) -> None:
        try:
            self.active_workspace_id = workspace_id
            root = self.query_one("#root-tabs", TabbedContent)
            root.active = workspace_id
            
            # Update active pill button style
            for ws, bid, _ in WORKSPACES:
                btn = self.query_one(f"#{bid}", Button)
                if ws == workspace_id:
                    btn.remove_class("btn-ws")
                    btn.add_class("btn-ws-active")
                else:
                    btn.remove_class("btn-ws-active")
                    btn.add_class("btn-ws")
            self.notify(f"Workspace: {workspace_id.replace('tab-', '').upper()}")
        except Exception:
            pass

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

    async def _auto_analyze_delayed(self, url: str):
        try:
            await asyncio.sleep(0.7)
            await self.action_analyze_url()
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def action_analyze_target(self):
        await self.action_analyze_url()

    def update_flag_display(self):
        try:
            all_flags = self.flag_tracker.get_all_flags()
            lbl = self.query_one("#lbl-flags", Label)
            lbl.update(f"FLAG: {len(all_flags)}")
            
            txt_flags = self.query_one("#txt-all-flags", TextArea)
            if all_flags:
                txt_flags.text = "\n".join([f"[{idx+1}] {f}" for idx, f in enumerate(all_flags)])
        except Exception:
            pass

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
        # Workspace Navigation Buttons
        if bid == "btn-ws-1":
            self.action_jump_workspace("tab-inspector")
        elif bid == "btn-ws-2":
            self.action_jump_workspace("tab-network")
        elif bid == "btn-ws-3":
            self.action_jump_workspace("tab-repeater")
        elif bid == "btn-ws-4":
            self.action_jump_workspace("tab-exploit")
        elif bid == "btn-ws-5":
            self.action_jump_workspace("tab-scripting")
        elif bid == "btn-ws-6":
            self.action_jump_workspace("tab-decoders")
        elif bid == "btn-analyze":
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
        elif bid == "btn-scan-comments":
            self.action_scan_comments_secrets()
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
            self.handle_jwt_parse()
        elif bid == "btn-flask":
            self.handle_flask_session()
        elif bid == "btn-hash":
            self.handle_hash_id()
        # WebSocket buttons
        elif bid == "btn-ws-connect":
            await self.action_ws_connect()
        elif bid == "btn-ws-disconnect":
            await self.action_ws_disconnect()
        elif bid == "btn-ws-send":
            await self.action_ws_send()
        # OOB buttons
        elif bid == "btn-oob-start":
            await self.action_oob_start()
        elif bid == "btn-oob-stop":
            await self.action_oob_stop()
        # Session buttons
        elif bid == "btn-save-session":
            self.action_save_session()
        # JS Console buttons
        elif bid == "btn-js-run":
            await self.action_run_js()
        elif bid == "btn-js-preload":
            await self.action_preload_js_scripts()
        elif bid == "btn-js-deobf":
            self.action_deobfuscate_js()
        elif bid == "btn-js-clear":
            self.query_one("#txt-js-input", TextArea).text = ""
        # Network Log buttons
        elif bid == "btn-net-replay":
            self.action_replay_network_entry()
        elif bid == "btn-net-curl":
            self.action_export_network_curl()
        elif bid == "btn-net-csrf":
            self.action_generate_csrf_poc()
        elif bid == "btn-net-clear":
            self.network_logger.clear()
            self.refresh_network_table()

    # ---------------------------------------------------------
    # Core Analysis & Recon
    # ---------------------------------------------------------
    async def action_analyze_url(self):
        url = self.query_one("#target-url", Input).value.strip()
        if not url:
            self.notify("Please enter a target URL", severity="warning")
            return

        self.initial_url = url
        self.query_one("#rep-url", Input).value = url
        self.notify(f"Analyzing {url}...", timeout=2)
        try:
            dom = DOMAnalyzer(url, self.flag_tracker, self.cookie_storage)
            resp = await dom.fetch_and_parse()
        except Exception as e:
            self.notify(f"Failed to connect to target: {e}", severity="error")
            return

        self.current_html = resp.body
        self.update_flag_display()

        # Update DOM Elements Tree
        tree = self.query_one("#tree-dom", Tree)
        build_dom_tree(tree, resp.body, hidden_only=self.dom_hidden_only)

        # 1. Update Comments & Hidden Forms
        comm_lines = [f"• {c}" for c in dom.comments]
        self.query_one("#txt-comments", TextArea).text = "\n".join(comm_lines) if comm_lines else "No HTML comments found."

        form_lines = []
        for f in dom.forms:
            form_lines.append(f"Form: {f['method']} {f['action']}")
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

        # 6. Start recon scanner asynchronously in background
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
        self.notify("Running CTF Recon Scanner in background...", timeout=2)
        scanner = CTFScanner(url, self.flag_tracker)
        results = await scanner.scan_all()
        self.probe_results = results
        
        tbl = self.query_one("#tbl-recon", DataTable)
        tbl.clear()
        for r in results:
            flags = ", ".join(r.flags) if r.flags else "-"
            snippet = r.body_snippet.replace("\n", " ")[:30] if r.body_snippet else ""
            tbl.add_row(str(r.status_code), r.path, f"{r.content_length}b", flags, snippet)
        
        # Display tech stack
        tech_lines = [f"{k}: {v}" for k, v in scanner.tech_stack.items()]
        self.query_one("#txt-tech-stack", TextArea).text = "\n".join(tech_lines) if tech_lines else "No sensitive disclosure headers."
        self.update_flag_display()

        # Automatically inspect the first discovered sensitive file
        if results:
            self.display_selected_probe(0)

    # ---------------------------------------------------------
    # DOM Tree Actions
    # ---------------------------------------------------------
    def display_selected_dom_node(self, node: TreeNode):
        if not node or not hasattr(node, "data") or node.data is None:
            return
        tag = node.data
        self.selected_dom_tag = tag
        attr_text = format_tag_details(tag)
        self.query_one("#txt-node-attrs", TextArea).text = attr_text
        outer_html = str(tag)[:10000]
        self.query_one("#txt-node-html", TextArea).text = outer_html

    def action_search_dom_tree(self):
        query = self.query_one("#inp-dom-search", Input).value.strip()
        tree = self.query_one("#tree-dom", Tree)
        build_dom_tree(tree, self.current_html, filter_query=query, hidden_only=self.dom_hidden_only)
        self.notify(f"Filtered DOM tree: '{query}'" if query else "Reset DOM tree filter")

    def action_toggle_hidden_dom(self):
        self.dom_hidden_only = not self.dom_hidden_only
        btn = self.query_one("#btn-dom-hidden", Button)
        btn.label = "[ Hidden: ON ]" if self.dom_hidden_only else "[ Hidden Only ]"
        query = self.query_one("#inp-dom-search", Input).value.strip()
        tree = self.query_one("#tree-dom", Tree)
        build_dom_tree(tree, self.current_html, filter_query=query, hidden_only=self.dom_hidden_only)
        self.notify(f"Showing {'only hidden elements' if self.dom_hidden_only else 'all elements'}")

    def action_refresh_dom_tree(self):
        query = self.query_one("#inp-dom-search", Input).value.strip()
        tree = self.query_one("#tree-dom", Tree)
        build_dom_tree(tree, self.current_html, filter_query=query, hidden_only=self.dom_hidden_only)
        self.notify("Re-parsed HTML DOM tree!")

    def action_copy_dom_outer_html(self):
        if not self.selected_dom_tag:
            self.notify("Select an element in the DOM tree first", severity="warning")
            return
        outer = str(self.selected_dom_tag)
        self._copy_to_system_clipboard(outer)
        self.notify(f"Copied <{self.selected_dom_tag.name}> outer HTML to clipboard!")

    # ---------------------------------------------------------
    # Sources, Probes, Downloads
    # ---------------------------------------------------------
    def display_selected_probe(self, row_idx: int):
        if not (0 <= row_idx < len(self.probe_results)):
            return
        probe = self.probe_results[row_idx]
        self.current_probe_url = probe.url
        lbl = self.query_one("#lbl-probe-file", Label)
        lbl.update(f"Selected File: {probe.path} ({probe.status_code}, {probe.content_length} bytes)")
        viewer = self.query_one("#txt-probe-content", TextArea)
        if probe.body_snippet:
            viewer.text = f"=== SENSITIVE FILE PROBE: {probe.url} ===\n\n{probe.body_snippet}"
        else:
            viewer.text = f"=== SENSITIVE FILE PROBE: {probe.url} ===\n\n(No body returned - Status {probe.status_code})"

    async def action_fetch_selected_probe(self):
        if not self.current_probe_url:
            self.notify("Select a probe file in the table first", severity="warning")
            return
        viewer = self.query_one("#txt-probe-content", TextArea)
        viewer.text = f"Fetching full content from: {self.current_probe_url}..."
        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            try:
                r = await client.get(self.current_probe_url)
                flags = self.flag_tracker.scan(r.text)
                self.update_flag_display()
                flag_str = f"\n[Captured Flags: {', '.join(flags)}]" if flags else ""
                viewer.text = f"=== FULL CONTENT: {self.current_probe_url} (HTTP {r.status_code}) ==={flag_str}\n\n{r.text}"
                self.notify(f"Fetched {len(r.content)} bytes from {self.current_probe_url}")
            except Exception as e:
                viewer.text = f"[!] Failed to fetch full probe content: {e}"

    def action_send_probe_to_repeater(self):
        if not self.current_probe_url:
            self.notify("Select a probe file in the table first", severity="warning")
            return
        self.query_one("#rep-url", Input).value = self.current_probe_url
        self.query_one("#rep-method", Input).value = "GET"
        self.action_jump_workspace("tab-repeater")
        self.notify("Sent probe URL to Repeater!")

    def action_copy_probe_curl(self):
        if not self.current_probe_url:
            return
        cmd = f'curl -i -k "{self.current_probe_url}"'
        self._copy_to_system_clipboard(cmd)
        self.notify("Copied cURL command for probe to clipboard!")

    def action_scan_probe_secrets(self):
        viewer = self.query_one("#txt-probe-content", TextArea)
        content = viewer.text
        if not content:
            return
        flags = self.flag_tracker.scan(content)
        if flags:
            self.update_flag_display()
            self.notify(f"Captured Flag: {', '.join(flags)}", severity="warning", timeout=5)
        else:
            self.notify("No new flags detected in probe content")

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

    async def action_download_selected_asset(self):
        tbl = self.query_one("#tbl-assets", DataTable)
        row_idx = tbl.cursor_row
        url = None
        if 0 <= row_idx < len(self.discovered_assets):
            url = self.discovered_assets[row_idx]["url"]
        elif self.current_asset_url:
            url = self.current_asset_url

        if not url:
            self.notify("Select a file in the table first.", severity="warning")
            return

        parsed_path = urllib.parse.urlparse(url).path
        raw_name = parsed_path.rstrip("/").split("/")[-1].split("?")[0] or "download"
        safe_name = re.sub(r"[^\w.\-]", "_", raw_name)[:120] or "download"

        dest_dir = self.downloads_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / safe_name

        counter = 1
        stem = dest_path.stem
        suffix = dest_path.suffix
        while dest_path.exists():
            dest_path = dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1

        lbl = self.query_one("#lbl-asset-info", Label)
        lbl.update(f"Downloading: {safe_name}...")

        async with httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True) as client:
            try:
                r = await client.get(url)
                dest_path.write_bytes(r.content)
                size_kb = len(r.content) / 1024
                lbl.update(f"Saved: {safe_name} ({size_kb:.1f} KB) -> {self.downloads_dir}")
                self.notify(f"Downloaded: {safe_name} ({size_kb:.1f} KB)", timeout=5)
                try:
                    text = r.content.decode("utf-8", errors="ignore")
                    flags = self.flag_tracker.scan(text)
                    if flags:
                        self.notify(f"FLAG in download: {', '.join(flags)}", severity="warning", timeout=8)
                    self.update_flag_display()
                except Exception:
                    pass
            except Exception as e:
                self.notify(f"Download failed: {e}", severity="error")
                lbl.update(f"Download failed: {e}")

    async def fetch_asset(self, url: str):
        self.current_asset_url = url
        lbl = self.query_one("#lbl-asset-info", Label)
        filename = url.split('/')[-1].split('?')[0] or url
        lbl.update(f"Fetching: {filename}...")
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
                flag_note = f" [FLAG: {', '.join(flags)}]" if flags else ""
                lbl.update(f"{filename} ({len(r.content)} bytes){flag_note}")
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
                        viewer.text = (
                            f"=== SOURCE MAP FOUND: {map_url} ===\n\n"
                            f"Original Unminified Source Files ({len(sources)}):\n"
                            + "\n".join([f"  • {s}" for s in sources])
                            + "\n\nFull Map JSON:\n" + r.text[:20000]
                        )
                        self.notify("Source map found & unminified!", severity="warning", timeout=5)
                    except Exception:
                        viewer.text = f"=== SOURCE MAP FOUND ({r.status_code}) ===\n\n{r.text[:20000]}"
                else:
                    viewer.text = f"[!] Source map not found at: {map_url} (HTTP {r.status_code})"
            except Exception as e:
                viewer.text = f"[!] Error probing source map: {e}"

    def action_copy_asset_curl(self):
        if not self.current_asset_url:
            return
        cmd = f'curl -i -k "{self.current_asset_url}"'
        self._copy_to_system_clipboard(cmd)
        self.notify("Copied cURL command to clipboard!")

    def action_send_asset_to_repeater(self):
        if not self.current_asset_url:
            return
        self.query_one("#rep-url", Input).value = self.current_asset_url
        self.query_one("#rep-method", Input).value = "GET"
        self.action_jump_workspace("tab-repeater")
        self.notify("Sent asset URL to Repeater!")

    # ---------------------------------------------------------
    # Comments & Secrets
    # ---------------------------------------------------------
    async def action_refresh_comments(self):
        url = self.query_one("#target-url", Input).value.strip()
        if not url:
            return
        self.notify("Harvesting comments across all pages and scripts...", timeout=2)
        if self.comments_gatherer:
            await self.comments_gatherer.gather_all(self.current_html)
            self.raw_comments_report = self.comments_gatherer.format_report()
            self.query_one("#txt-comments", TextArea).text = self.raw_comments_report
            self.update_flag_display()
            self.notify("Comments harvested!")

    def action_scan_comments_secrets(self):
        if not self.comments_gatherer:
            return
        secrets = self.comments_gatherer.scan_secrets()
        if secrets:
            lines = [f"• [{s['category']}] ({s['source']}): {s['match']}" for s in secrets]
            self.query_one("#txt-comments", TextArea).text = "=== HIGH-CONFIDENCE SECRETS & LEAKS ===\n\n" + "\n".join(lines)
            self.notify(f"Found {len(secrets)} potential secrets in comments!", severity="warning", timeout=5)
        else:
            self.notify("No obvious API keys or credentials detected in comments")

    # ---------------------------------------------------------
    # Cookie & Storage Management
    # ---------------------------------------------------------
    def update_cookies_display(self):
        tbl = self.query_one("#tbl-cookies", DataTable)
        tbl.clear()
        for name, val in self.cookie_storage.cookies.items():
            tbl.add_row(name, val[:30] + ("..." if len(val) > 30 else ""), "/", "False")

    def update_storage_display(self):
        tbl = self.query_one("#tbl-storage", DataTable)
        tbl.clear()
        for item in self.cookie_storage.local_storage:
            tbl.add_row("localStorage", item["key"], item["value"][:25], item.get("source", "HTML"))
        for item in self.cookie_storage.session_storage:
            tbl.add_row("sessionStorage", item["key"], item["value"][:25], item.get("source", "HTML"))

    def action_set_cookie(self):
        name = self.query_one("#inp-cookie-name", Input).value.strip()
        val = self.query_one("#inp-cookie-val", Input).value.strip()
        if name:
            self.cookie_storage.set_cookie(name, val)
            self.update_cookies_display()
            self.notify(f"Set cookie: {name}")

    def action_delete_cookie(self):
        name = self.query_one("#inp-cookie-name", Input).value.strip()
        if name in self.cookie_storage.cookies:
            self.cookie_storage.del_cookie(name)
            self.update_cookies_display()
            self.notify(f"Deleted cookie: {name}")

    def action_decode_selected_cookie(self):
        tbl = self.query_one("#tbl-cookies", DataTable)
        row_idx = tbl.cursor_row
        names = list(self.cookie_storage.cookies.keys())
        if 0 <= row_idx < len(names):
            name = names[row_idx]
            val = self.cookie_storage.cookies[name]
        else:
            val = self.query_one("#inp-cookie-val", Input).value.strip()

        if not val:
            self.notify("Select a cookie or type a value to decode", severity="warning")
            return

        dec_text = f"=== COOKIE VALUE: {val} ===\n\n"
        b64 = base64_decode(val)
        if b64:
            dec_text += f"[+] Base64 Decoded:\n{b64}\n\n"
        jwt_res = inspect_jwt(val)
        if "error" not in jwt_res:
            dec_text += f"[+] JWT Header:\n{json.dumps(jwt_res.get('header'), indent=2)}\n\n"
            dec_text += f"[+] JWT Payload:\n{json.dumps(jwt_res.get('payload'), indent=2)}\n\n"
            if jwt_res.get("analysis"):
                dec_text += f"[!] JWT Alerts:\n" + "\n".join([f"  • {a}" for a in jwt_res["analysis"]]) + "\n\n"
        flask_res = unpack_flask_session(val)
        if "error" not in flask_res:
            dec_text += f"[+] Flask Session Payload:\n{json.dumps(flask_res, indent=2)}\n\n"
        u_dec = url_decode(val)
        if u_dec != val:
            dec_text += f"[+] URL Decoded:\n{u_dec}\n\n"

        self.query_one("#txt-cookie-decoded", TextArea).text = dec_text

    def action_set_global_header(self):
        name = self.query_one("#inp-hdr-name", Input).value.strip()
        val = self.query_one("#inp-hdr-val", Input).value.strip()
        if name and val:
            self.cookie_storage.set_header(name, val)
            hdrs = "\n".join([f"{k}: {v}" for k, v in self.cookie_storage.global_headers.items()])
            self.query_one("#txt-global-headers", TextArea).text = hdrs
            self.notify(f"Set global header: {name}")

    def action_clear_global_headers(self):
        self.cookie_storage.global_headers.clear()
        self.query_one("#txt-global-headers", TextArea).text = ""
        self.notify("Cleared global headers")

    # ---------------------------------------------------------
    # Repeater Actions
    # ---------------------------------------------------------
    async def action_send_repeater(self):
        method = self.query_one("#rep-method", Input).value.strip().upper()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        if not url:
            return

        headers = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        self.notify("Sending request...", timeout=1)
        resp = await self.repeater_engine.send(method, url, headers, body)
        self.refresh_network_table()

        self.query_one("#lbl-rep-status", Label).update(
            f"Status: {resp.status_code} | Time: {resp.elapsed_ms:.1f}ms | Length: {len(resp.body)} bytes"
        )

        flags_found = self.flag_tracker.scan(resp.body)
        self.update_flag_display()
        flag_header = f"CAPTURED FLAGS: {', '.join(flags_found)}\n\n" if flags_found else ""

        hdr_lines = [f"{k}: {v}" for k, v in resp.headers.items()]
        full_text = f"HTTP/1.1 {resp.status_code}\n" + "\n".join(hdr_lines) + f"\n\n{flag_header}" + resp.body
        self.query_one("#rep-response", TextArea).text = full_text

    def action_copy_curl(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        headers = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        cmd = self.repeater_engine.to_curl(method, url, headers, body)
        self._copy_to_system_clipboard(cmd)
        self.notify("Copied cURL command to clipboard!")

    def action_copy_python(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        headers = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        script = self.repeater_engine.to_python(method, url, headers, body)
        self.query_one("#rep-response", TextArea).text = "=== GENERATED PYTHON EXPLOIT SCRIPT ===\n\n" + script
        self.notify("Generated Python exploit script in Response pane!")

    async def action_run_fuzzer(self):
        method = self.query_one("#rep-method", Input).value.strip()
        url = self.query_one("#rep-url", Input).value.strip()
        headers_raw = self.query_one("#rep-headers", TextArea).text
        body = self.query_one("#rep-body", TextArea).text
        headers = {}
        for line in headers_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        self.notify("Running Repeater Fuzzer with 100+ CTF payloads...", timeout=2)
        results = await self.repeater_engine.fuzz(method, url, headers, body)
        self.refresh_network_table()

        lines = ["=== FUZZ RESULTS (Sorted by Anomalies) ==="]
        for r in results[:40]:
            flag_str = f" [FLAG: {', '.join(r.flags)}]" if r.flags else ""
            lines.append(f"Payload: {r.payload:<25} | Status: {r.status_code} | Size: {len(r.body)}b | Time: {r.elapsed_ms:.1f}ms{flag_str}")
        self.query_one("#rep-response", TextArea).text = "\n".join(lines)
        self.update_flag_display()

    # ---------------------------------------------------------
    # cURL Studio Actions
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

        status_text = f"Exit Code: {code} | Latency: {elapsed_ms:.1f}ms | Output Size: {len(stdout)} bytes"
        self.query_one("#lbl-curl-meta", Label).update(status_text)

        flags = self.flag_tracker.scan(stdout + "\n" + stderr)
        if flags:
            self.update_flag_display()
            self.notify(f"FLAG DETECTED IN CURL OUTPUT: {', '.join(flags)}", timeout=5)

        output_parts = []
        if flags:
            output_parts.append(f"CAPTURED FLAG(S): {', '.join(flags)}\n\n")
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
        self.action_jump_workspace("tab-repeater")
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
        self._copy_to_system_clipboard(cmd)
        self.notify("Copied cURL command to clipboard!")

    def action_copy_curl_response(self):
        resp = self.query_one("#txt-curl-resp", TextArea).text
        self._copy_to_system_clipboard(resp)
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
        self.action_jump_workspace("tab-repeater")
        self.notify("Injected SQL payload into Repeater URL!")

    def action_sqli_to_curl(self):
        payload = self.query_one("#txt-sqli-editor", TextArea).text.strip()
        if not payload:
            return
        target = self.query_one("#target-url", Input).value.strip() or self.initial_url
        cmd = f'curl -i -k -G "{target.rstrip("/")}/" --data-urlencode "id={payload}"'
        self.query_one("#txt-curl-cmd", TextArea).text = cmd
        self.action_jump_workspace("tab-repeater")
        self.notify("Sent SQL payload to cURL Studio!")

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
            self.notify(f"FLAG IN PHP OUTPUT: {', '.join(flags)}", severity="warning", timeout=5)

        self.query_one("#txt-php-output", TextArea).text = output

    def load_selected_php_wrapper(self, row_idx: int):
        if not (0 <= row_idx < len(PHP_LFI_WRAPPERS)):
            return
        item = PHP_LFI_WRAPPERS[row_idx]
        self._copy_to_system_clipboard(item["wrapper"])
        self.notify(f"Copied wrapper: {item['name']}")

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
        self.action_jump_workspace("tab-repeater")
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
        self.action_jump_workspace("tab-repeater")
        self.notify("Sent payload to Repeater!")

    def action_payload_to_curl(self):
        payload = self.query_one("#txt-payload-view", TextArea).text.strip()
        if not payload:
            return
        target = self.query_one("#target-url", Input).value.strip() or self.initial_url
        cmd = f'curl -i -k -X POST "{target.rstrip("/")}/" -d "{payload}"'
        self.query_one("#txt-curl-cmd", TextArea).text = cmd
        self.action_jump_workspace("tab-repeater")
        self.notify("Sent payload to cURL Studio!")

    def action_copy_payload_string(self):
        payload = self.query_one("#txt-payload-view", TextArea).text.strip()
        self._copy_to_system_clipboard(payload)
        self.notify("Copied payload string to clipboard!")

    # ---------------------------------------------------------
    # Decoders
    # ---------------------------------------------------------
    def _get_dec_input(self) -> str:
        return self.query_one("#dec-input", TextArea).text.strip()

    def _set_dec_output(self, text: str):
        self.query_one("#dec-output", TextArea).text = text
        flags = self.flag_tracker.scan(text)
        if flags:
            self.update_flag_display()
            self.notify(f"FLAG FOUND IN DECODED OUTPUT: {', '.join(flags)}", severity="warning", timeout=6)

    def handle_decode(self, decode_func):
        self._set_dec_output(decode_func(self._get_dec_input()))

    def handle_jwt_parse(self):
        res = inspect_jwt(self._get_dec_input())
        self._set_dec_output(json.dumps(res, indent=2))

    def handle_flask_session(self):
        res = unpack_flask_session(self._get_dec_input())
        self._set_dec_output(json.dumps(res, indent=2))

    def handle_hash_id(self):
        res = identify_hash(self._get_dec_input())
        self._set_dec_output("\n".join(res))

    # ---------------------------------------------------------
    # WebSockets
    # ---------------------------------------------------------
    async def action_ws_connect(self):
        url = self.query_one("#ws-url", Input).value.strip()
        self.ws_mgr = WebSocketManager(url)
        self.notify(f"Connecting to WebSocket: {url}...")
        connected = await self.ws_mgr.connect()
        if connected:
            self.notify("Connected to WebSocket stream!", timeout=2)
            asyncio.create_task(self._listen_ws())
        else:
            self.notify("Failed to connect to WebSocket", severity="error")

    async def _listen_ws(self):
        log_view = self.query_one("#txt-ws-log", TextArea)
        while self.ws_mgr and self.ws_mgr.connected:
            frame = await self.ws_mgr.receive_frame()
            if frame:
                flags = self.flag_tracker.scan(frame.data)
                self.update_flag_display()
                flag_str = f" [FLAG: {', '.join(flags)}]" if flags else ""
                cur = log_view.text
                log_view.text = f"[{frame.timestamp}] <RECV> {frame.data}{flag_str}\n" + cur
            await asyncio.sleep(0.05)

    async def action_ws_disconnect(self):
        if self.ws_mgr:
            await self.ws_mgr.disconnect()
            self.notify("Disconnected from WebSocket")

    async def action_ws_send(self):
        payload = self.query_one("#ws-payload", Input).value.strip()
        if self.ws_mgr and self.ws_mgr.connected:
            await self.ws_mgr.send_frame(payload)
            log_view = self.query_one("#txt-ws-log", TextArea)
            log_view.text = f"[SENT] > {payload}\n" + log_view.text

    # ---------------------------------------------------------
    # OOB Callbacks
    # ---------------------------------------------------------
    async def action_oob_start(self):
        port_s = self.query_one("#oob-port", Input).value.strip()
        port = int(port_s) if port_s.isdigit() else 9999
        self.oob_listener = OOBListener(port, self.flag_tracker)
        ok = await self.oob_listener.start()
        if ok:
            self.notify(f"OOB Listener active on port {port}!")
            asyncio.create_task(self._poll_oob())
        else:
            self.notify(f"Could not bind to port {port}", severity="error")

    async def _poll_oob(self):
        tbl = self.query_one("#tbl-oob", DataTable)
        while self.oob_listener and self.oob_listener.running:
            if self.oob_listener.requests:
                tbl.clear()
                for req in self.oob_listener.requests:
                    tbl.add_row(req.timestamp, req.client_ip, req.method, req.path, req.body[:30])
                self.update_flag_display()
            await asyncio.sleep(1)

    async def action_oob_stop(self):
        if self.oob_listener:
            await self.oob_listener.stop()
            self.notify("OOB Listener stopped")

    # ---------------------------------------------------------
    # JS Console & Deobfuscator
    # ---------------------------------------------------------
    async def action_run_js(self):
        code = self.query_one("#txt-js-input", TextArea).text.strip()
        if not code:
            self.notify("Enter JavaScript code to execute", severity="warning")
            return
        self.notify("Evaluating JS sandbox...", timeout=1)
        res = await self.js_engine.evaluate(code, self.flag_tracker)
        
        self.query_one("#lbl-js-status", Label).update(
            f"Status: {'Success' if res.success else 'Error'} | Time: {res.elapsed_ms:.1f}ms"
        )
        
        flags = self.flag_tracker.scan(res.output + "\n" + res.error)
        if flags:
            self.update_flag_display()
            self.notify(f"FLAG DETECTED IN JS OUTPUT: {', '.join(flags)}", timeout=5)

        output_parts = []
        if flags:
            output_parts.append(f"CAPTURED FLAGS: {', '.join(flags)}\n\n")
        if res.output:
            output_parts.append(res.output)
        if res.error:
            output_parts.append(f"\n[Runtime Error]:\n{res.error}")
        if not res.output and not res.error:
            output_parts.append("(Script executed with no output - try console.log)")

        self.query_one("#txt-js-output", TextArea).text = "".join(output_parts)

    async def action_preload_js_scripts(self):
        if not self.discovered_assets:
            self.notify("Analyze target first to discover JS files", severity="warning")
            return
        js_urls = [a["url"] for a in self.discovered_assets if a["type"] == "JavaScript"]
        if not js_urls:
            self.notify("No external JS files discovered", severity="warning")
            return
        
        self.notify(f"Preloading {len(js_urls)} script(s) into sandbox...", timeout=2)
        count = await self.js_engine.preload_target_scripts(js_urls)
        self.notify(f"Preloaded {count} external scripts into sandbox environment!")

    def action_deobfuscate_js(self):
        code = self.query_one("#txt-js-input", TextArea).text
        if not code.strip():
            return
        deobf = deobfuscate_javascript(code)
        self.query_one("#txt-js-output", TextArea).text = (
            "=== DEOBFUSCATED JAVASCRIPT OUTPUT ===\n\n" + deobf
        )
        self.notify("Deobfuscated string encodings & hex literals!")

    # ---------------------------------------------------------
    # Network Traffic Logging & CSRF Generator
    # ---------------------------------------------------------
    def refresh_network_table(self):
        tbl = self.query_one("#tbl-network", DataTable)
        tbl.clear()
        for e in self.network_logger.entries:
            tbl.add_row(
                str(e.id),
                e.timestamp,
                e.method,
                str(e.status),
                f"{e.bytes_len}b",
                f"{e.latency_ms:.0f}ms",
                e.url
            )

    def display_selected_network_entry(self, row_idx: int):
        if not (0 <= row_idx < len(self.network_logger.entries)):
            return
        entry = self.network_logger.entries[row_idx]
        self.selected_network_entry = entry
        
        req_hdrs = "\n".join([f"  {k}: {v}" for k, v in entry.req_headers.items()])
        resp_hdrs = "\n".join([f"  {k}: {v}" for k, v in entry.resp_headers.items()])
        
        detail_text = (
            f"=== REQUEST #{entry.id}: {entry.method} {entry.url} ===\n"
            f"Time: {entry.timestamp} | Status: {entry.status} | Latency: {entry.latency_ms:.1f}ms\n\n"
            f"[Request Headers]:\n{req_hdrs or '  (None)'}\n\n"
            f"[Request Body]:\n{entry.req_body or '(Empty)'}\n\n"
            f"-----------------------------------------\n"
            f"[Response Headers]:\n{resp_hdrs or '  (None)'}\n\n"
            f"[Response Body Snippet]:\n{entry.resp_body or '(Empty)'}"
        )
        self.query_one("#txt-net-details", TextArea).text = detail_text

    def action_replay_network_entry(self):
        if not self.selected_network_entry:
            tbl = self.query_one("#tbl-network", DataTable)
            if 0 <= tbl.cursor_row < len(self.network_logger.entries):
                self.selected_network_entry = self.network_logger.entries[tbl.cursor_row]
        if not self.selected_network_entry:
            self.notify("Select a request in the Network log first", severity="warning")
            return
        
        e = self.selected_network_entry
        self.query_one("#rep-url", Input).value = e.url
        self.query_one("#rep-method", Input).value = e.method
        hdrs_str = "\n".join([f"{k}: {v}" for k, v in e.req_headers.items()])
        self.query_one("#rep-headers", TextArea).text = hdrs_str
        self.query_one("#rep-body", TextArea).text = e.req_body
        self.action_jump_workspace("tab-repeater")
        self.notify(f"Loaded Request #{e.id} into Repeater!")

    def action_export_network_curl(self):
        if not self.selected_network_entry:
            tbl = self.query_one("#tbl-network", DataTable)
            if 0 <= tbl.cursor_row < len(self.network_logger.entries):
                self.selected_network_entry = self.network_logger.entries[tbl.cursor_row]
        if not self.selected_network_entry:
            return
        e = self.selected_network_entry
        cmd = self.repeater_engine.to_curl(e.method, e.url, e.req_headers, e.req_body)
        self._copy_to_system_clipboard(cmd)
        self.notify(f"Copied cURL for Request #{e.id} to clipboard!")

    def action_generate_csrf_poc(self):
        if not self.selected_network_entry:
            tbl = self.query_one("#tbl-network", DataTable)
            if 0 <= tbl.cursor_row < len(self.network_logger.entries):
                self.selected_network_entry = self.network_logger.entries[tbl.cursor_row]
        if not self.selected_network_entry:
            self.notify("Select a POST/PUT request to generate CSRF PoC", severity="warning")
            return
        e = self.selected_network_entry
        poc = generate_csrf_poc(e.url, e.method, e.req_body)
        self.query_one("#txt-net-details", TextArea).text = (
            f"=== AUTOMATED CSRF HTML EXPLOIT POC FOR #{e.id} ===\n\n" + poc
        )
        self.notify("Generated CSRF PoC in Details pane!")

    # ---------------------------------------------------------
    # Session & Global Flag Display
    # ---------------------------------------------------------
    def action_save_session(self):
        s_name = self.query_one("#inp-session", Input).value.strip() or "challenge_1"
        data = {
            "initial_url": self.initial_url,
            "flags": self.flag_tracker.flags,
            "cookies": self.cookie_storage.cookies,
            "global_headers": self.cookie_storage.global_headers,
            "discovered_assets": self.discovered_assets,
            "network_log_count": len(self.network_logger.entries),
            "version": __version__
        }
        self.session_mgr.save_session(s_name, data)
        self.notify(f"Session '{s_name}' saved to disk!")

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
