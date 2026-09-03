#!/usr/bin/env bash
# ==============================================================================
#  CTF DevTools — Fast One-Line Installer (Linux / macOS / WSL)
# ==============================================================================
set -e

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║          🛡️   CTF DevTools v1.0.0 — Automated Installer   🛡️          ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Detect Python 3
echo -e "${BLUE}[*] Checking Python installation...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo -e "${RED}[!] Error: Python 3 is not installed or not in PATH.${NC}"
    echo "    Please install Python 3.10 or newer (https://www.python.org/downloads/)"
    exit 1
fi

PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON_BIN -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON_BIN -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo -e "${RED}[!] Error: Python 3.10+ required. Found Python $PY_VER.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Detected Python $PY_VER ($PYTHON_BIN)${NC}"

# 2. Detect pip
echo -e "${BLUE}[*] Checking pip...${NC}"
if ! $PYTHON_BIN -m pip --version &>/dev/null; then
    echo -e "${YELLOW}[!] pip not found. Attempting to install pip via ensurepip...${NC}"
    $PYTHON_BIN -m ensurepip --default-pip || true
fi

# 3. Install Package
echo -e "${BLUE}[*] Installing CTF DevTools...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if $PYTHON_BIN -m pip install -e . --break-system-packages &>/dev/null; then
    echo -e "${GREEN}[+] Installed successfully (editable mode)!${NC}"
elif $PYTHON_BIN -m pip install -e . &>/dev/null; then
    echo -e "${GREEN}[+] Installed successfully (editable mode)!${NC}"
elif $PYTHON_BIN -m pip install --user -e . &>/dev/null; then
    echo -e "${GREEN}[+] Installed successfully (user space)!${NC}"
else
    echo -e "${YELLOW}[!] Standard install failed, trying virtualenv approach...${NC}"
    $PYTHON_BIN -m venv .venv
    source .venv/bin/activate
    pip install -e .
    echo -e "${GREEN}[+] Installed inside dedicated .venv environment!${NC}"
fi

# 4. Check Optional Tools
echo ""
echo -e "${CYAN}[*] Checking Recommended Companion Tools:${NC}"
for tool in curl php node; do
    if command -v $tool &>/dev/null; then
        echo -e "  • ${GREEN}✓ $tool${NC} : $(which $tool)"
    else
        echo -e "  • ${YELLOW}○ $tool${NC} : Not found (optional, used for local sandbox execution)"
    fi
done

# 5. Create default download directory
DL_DIR="${HOME}/CTF/sandbox/ctf-dev-downloads"
mkdir -p "$DL_DIR"
echo -e "  • ${GREEN}✓ Downloads Dir${NC} : $DL_DIR"

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  🎉 CTF DevTools is Ready to Launch!${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Launch the workstation with:"
echo -e "  ${CYAN}${BOLD}ctf-dev <TARGET_URL>${NC}   or   ${CYAN}${BOLD}ctf-devtools <TARGET_URL>${NC}"
echo ""
echo -e "Examples:"
echo -e "  ctf-dev http://challenge.picoctf.net:12345"
echo -e "  ctf-dev --decode \"eyJhbGciOiJIUzI1NiJ9...\""
echo -e "  ctf-dev http://target.ctf/ --scan-only"
echo ""
