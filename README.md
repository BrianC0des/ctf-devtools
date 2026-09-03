# 🛡️ CTF DevTools — Terminal Offensive Workstation

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/BrianC0des/ctf-devtools)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20WSL-purple.svg)]()

**CTF DevTools** is a lightweight terminal workstation and web security suite designed for rapid vulnerability analysis, web exploitation, and Capture The Flag (CTF) challenges.

Inspired by browser DevTools, Burp Suite, and CyberChef, **CTF DevTools** combines recon scanners, DOM element tree inspectors, binary asset downloaders, interactive repeaters, multi-engine SQL injection workbenches, local PHP sandboxes, and a universal payload library directly inside your terminal.

---

## 🚀 Key Features

| Tab | Capability | Highlights |
|---|---|---|
| ** Recon** | Sensitive Path & Probes | Scans 40+ sensitive files (`.git`, `.env`, `robots.txt`, backup files), detects tech headers, and previews leaks. |
| ** Elements** | Full HTML DOM Tree | Interactive hierarchy tree, hidden element detection (`display:none`, `type="hidden"`), tag attribute inspector, and outerHTML copy. |
| ** Comments & Secrets** | Comment Harvester | Extracts HTML and JS comments across all scripts, scrapes form inputs, and scans for hardcoded API keys. |
| ** Sources & Files** | Asset Inspector & Downloader | Discovers scripts, images, CSS, and documents with a **1-click binary downloader** (saving images, GIFs, and PDFs to `ctf-dev-downloads/`) and `.map` unminifier. |
| ** Storage & Cookies** | Storage & Auth Harvester | Auto-captures cookies, decodes JWT / Flask signed session tokens, manages global headers, and harvests `localStorage`. |
| ** Crawler** | Spider & Endpoint Discovery | Recursively maps internal routes and extracts hidden JavaScript API endpoints. |
| ** Repeater** | Request Composer & Fuzzer | Compose HTTP requests, fuzz injection points with `FUZZ` / `fzz`, and auto-convert to cURL or standalone Python httpx scripts. |
| ** cURL** | Workshop & Formatter | Execute live cURL commands, beautify multi-line backslash formats (`⇥ Format`), and load 15+ premade CTF bypass templates. |
| **💉 SQLi** | Dialects & WAF Tamper | Multi-DBMS crafter (SQLite, MySQL, Postgres, MSSQL, Oracle), UNION & ORDER BY column fuzzer, and WAF bypass encoders (`/**/`, `/*!MySQL*/`, `0xHex`, `CHAR()`, `%0a`, URL encode). |
| **🐘 PHP** | Sandbox & Gadgets | Live asynchronous PHP script runner, `0e...` loose comparison magic hash table, LFI wrapper catalog (`php://filter`, `data://`), and POP chain serializers. |
| **🎯 Payloads** | Universal Payload Vault | Searchable cheat-sheet covering XSS (polyglots, bypasses), SSTI (Jinja2, Twig, Spring), Command Injection, Reverse Shells, File Uploads, SSRF, and NoSQL. |
| ** Decoders** | CyberChef-Lite | Base64, Hex, URL, ROT13, JWT Inspector, Flask session unpacker, and hash type identifier. |
| ** Console** | JS Sandbox & Deobfuscator | Preloads target scripts into a local Node.js environment, provides DOM mocking, and deobfuscates hex/unicode literals. |
| **󰒋 Network** | Traffic History & CSRF PoC | Complete HTTP log with latency and status, 1-click repeater replay, and **automated CSRF HTML exploit generator**. |
| ** WebSockets** | Live Frame Stream | Connects to WebSocket streams, logs bidirectional frames, and sends custom payloads. |
| ** Callbacks** | OOB HTTP Listener | Built-in local HTTP listener for catching blind SSRF, XSS, and XXE exfiltrations with real-time flag extraction. |

---

## 📦 Installation

### ⚡ 1-Line Quick Install

#### Linux / macOS / WSL:
```bash
curl -sSL https://raw.githubusercontent.com/BrianC0des/ctf-devtools/main/install.sh | bash
```

#### Windows (PowerShell):
```powershell
irm https://raw.githubusercontent.com/BrianC0des/ctf-devtools/main/install.ps1 | iex
```

---

### 🔧 Manual Installation (from Git)

#### Prerequisites
- Python 3.10 or higher
- Optional: `curl`, `php` (for local PHP sandbox), `node` (for JS console)

#### Linux / macOS / WSL
```bash
git clone https://github.com/BrianC0des/ctf-devtools.git
cd ctf-devtools
./install.sh
# Or manually: pip install -e .
```

#### Windows (Command Prompt / PowerShell)
```powershell
git clone https://github.com/BrianC0des/ctf-devtools.git
cd ctf-devtools
.\install.ps1
# Or manually: pip install -e .
```
*Note: On Windows, CTF DevTools automatically enables VT100 ANSI sequences and UTF-8 console output for crystal-clear visuals.*

---

## ⚡ Quick Start

### Interactive TUI Mode
Launch the workstation against your CTF target:
```bash
ctf-dev http://challenge.picoctf.net:12345
```
*(Or use `ctf-devtools <URL>`)*

### Fast CLI Recon (Scan-Only)
Run a quick background probe scan without opening the TUI:
```bash
ctf-dev http://challenge.picoctf.net:12345 --scan-only
```

### CLI Instant Decoder
Decode tokens or inspect hashes directly from the command line:
```bash
ctf-dev --decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"
```

---

## ⌨️ Keybindings & Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl + S` | Send Repeater Request |
| `Ctrl + E` | Execute cURL Command |
| `Ctrl + B` | Execute PHP Script |
| `Ctrl + J` | Run JavaScript in Console |
| `Ctrl + R` | Trigger Recon Scanner |
| `Ctrl + Q` | Quit Application |

---

## 🛠️ Configuration & Downloads Directory

Downloaded files (images, GIFs, PDFs, scripts) from the **Sources & Files** tab are automatically saved to:
- **Linux/macOS:** `~/CTF/sandbox/ctf-dev-downloads/` (or customizable via `CTF_DEV_DOWNLOADS` env var)
- **Windows:** `%USERPROFILE%\CTF\ctf-dev-downloads\`

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

Developed by [BrianC0des](https://github.com/BrianC0des).
