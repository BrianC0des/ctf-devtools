from __future__ import annotations
"""Cross-platform compatibility utilities for Windows (native & WSL), Linux, and macOS."""
import os
import sys
import shutil
import pathlib
import tempfile
from typing import Optional

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

def init_platform():
    """Initializes platform-specific console and encoding settings."""
    if IS_WINDOWS:
        # Enable Windows VT100 / ANSI escape sequences if available
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # STD_OUTPUT_HANDLE = -11
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

        # Set console output encoding to utf-8
        try:
            if sys.stdout.encoding != "utf-8":
                sys.stdout.reconfigure(encoding="utf-8")
            if sys.stderr.encoding != "utf-8":
                sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

def get_default_downloads_dir() -> pathlib.Path:
    """Returns the platform-appropriate downloads directory."""
    custom = os.environ.get("CTF_DEV_DOWNLOADS")
    if custom:
        p = pathlib.Path(custom)
    elif os.path.exists("/home/devchan/CTF/sandbox/ctf-dev-downloads"):
        p = pathlib.Path("/home/devchan/CTF/sandbox/ctf-dev-downloads")
    else:
        p = pathlib.Path.home() / "CTF" / "ctf-dev-downloads"

    p.mkdir(parents=True, exist_ok=True)
    return p

def find_binary(name: str) -> Optional[str]:
    """Finds an executable binary across Windows/Linux/macOS PATH."""
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS and not name.lower().endswith((".exe", ".cmd", ".bat")):
        for ext in [".exe", ".cmd", ".bat"]:
            cand = shutil.which(f"{name}{ext}")
            if cand:
                return cand
    return None
