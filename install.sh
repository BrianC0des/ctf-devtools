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

# 2. Check Git & Setup Source Directory
INSTALL_DIR="${HOME}/.ctf-devtools"
if [ -f "pyproject.toml" ] && [ -d "ctf_devtools" ]; then
    TARGET_DIR="$(pwd)"
    echo -e "${BLUE}[*] Installing from local directory: $TARGET_DIR${NC}"
else
    echo -e "${BLUE}[*] Downloading CTF DevTools from GitHub...${NC}"
    if command -v git &>/dev/null; then
        if [ -d "$INSTALL_DIR/.git" ]; then
            echo -e "${CYAN}[*] Updating existing installation in $INSTALL_DIR...${NC}"
            git -C "$INSTALL_DIR" pull --quiet || true
        else
            mkdir -p "$INSTALL_DIR"
            git clone --quiet https://github.com/BrianC0des/ctf-devtools.git "$INSTALL_DIR"
        fi
        TARGET_DIR="$INSTALL_DIR"
    else
        echo -e "${BLUE}[*] Git not found, installing directly via pip from GitHub...${NC}"
        $PYTHON_BIN -m pip install "git+https://github.com/BrianC0des/ctf-devtools.git" --break-system-packages || \
        $PYTHON_BIN -m pip install "git+https://github.com/BrianC0des/ctf-devtools.git" --user || \
        $PYTHON_BIN -m pip install "git+https://github.com/BrianC0des/ctf-devtools.git"
        TARGET_DIR=""
    fi
fi

# 3. Install Package
if [ -n "$TARGET_DIR" ]; then
    cd "$TARGET_DIR"
    echo -e "${BLUE}[*] Installing dependencies and CLI entrypoints...${NC}"
    if $PYTHON_BIN -m pip install -e . --break-system-packages &>/dev/null; then
        echo -e "${GREEN}[+] Installed successfully!${NC}"
    elif $PYTHON_BIN -m pip install -e . &>/dev/null; then
        echo -e "${GREEN}[+] Installed successfully!${NC}"
    elif $PYTHON_BIN -m pip install --user -e . &>/dev/null; then
        echo -e "${GREEN}[+] Installed successfully in user space!${NC}"
    else
        echo -e "${YELLOW}[*] Setting up dedicated venv environment in $TARGET_DIR/.venv ...${NC}"
        $PYTHON_BIN -m venv .venv
        .venv/bin/pip install -e .
        mkdir -p "${HOME}/.local/bin"
        ln -sf "${TARGET_DIR}/.venv/bin/ctf-dev" "${HOME}/.local/bin/ctf-dev"
        ln -sf "${TARGET_DIR}/.venv/bin/ctf-devtools" "${HOME}/.local/bin/ctf-devtools"
        echo -e "${GREEN}[+] Created shims in ~/.local/bin/ !${NC}"
    fi
fi

# 4. Check PATH for ~/.local/bin
if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
    export PATH="${HOME}/.local/bin:$PATH"
fi

# 5. Check Optional Tools
echo ""
echo -e "${CYAN}[*] Checking Recommended Companion Tools:${NC}"
for tool in curl php node; do
    if command -v $tool &>/dev/null; then
        echo -e "  • ${GREEN}✓ $tool${NC} : $(which $tool)"
    else
        echo -e "  • ${YELLOW}○ $tool${NC} : Not found in PATH (optional, for local script sandboxes)"
    fi
done

# 6. Create default download directory
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
