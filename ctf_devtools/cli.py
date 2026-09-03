"""CLI entrypoint for CTF DevTools."""
import argparse
import asyncio
import sys
from . import __version__
from .app import CTFDevToolsApp
from .decoders import base64_decode, url_decode, hex_decode, inspect_jwt, unpack_flask_session, identify_hash
from .scanner import CTFScanner
from .platform_compat import init_platform

def main():
    init_platform()
    parser = argparse.ArgumentParser(
        prog="ctf-devtools",
        description="CTF DevTools: Terminal Web DevTools & Offensive Workstation"
    )
    parser.add_argument("-v", "--version", action="version", version=f"CTF DevTools v{__version__}")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8000", help="Target URL (e.g. http://challenge.ctf:8080)")
    parser.add_argument("--scan-only", action="store_true", help="Run fast CLI recon scan without launching TUI")
    parser.add_argument("--decode", help="Quickly decode a string or token in CLI")

    args = parser.parse_args()

    if args.decode:
        print(f"[*] Analyzing token/string: {args.decode}\n")
        print("[Hash Identification]:", ", ".join(identify_hash(args.decode)))
        print("[Base64 Decoded]:", base64_decode(args.decode))
        print("[URL Decoded]:", url_decode(args.decode))
        jwt_res = inspect_jwt(args.decode)
        if "error" not in jwt_res:
            print("[JWT Header]:", jwt_res.get("header"))
            print("[JWT Payload]:", jwt_res.get("payload"))
            if jwt_res.get("analysis"):
                print("[JWT Alerts]:", jwt_res.get("analysis"))
        flask_res = unpack_flask_session(args.decode)
        if "error" not in flask_res:
            print("[Flask Session]:", flask_res)
        sys.exit(0)

    if args.scan_only:
        print(f"[*] Starting CTF Recon Scan against: {args.url}\n")
        scanner = CTFScanner(args.url)
        results = asyncio.run(scanner.scan_all())
        if scanner.tech_stack:
            print("[+] Disclosed Tech Headers:")
            for k, v in scanner.tech_stack.items():
                print(f"    {k}: {v}")
            print()
        print(f"{'STATUS':<8} {'PATH':<25} {'SIZE':<10} {'FLAGS'}")
        print("-" * 55)
        for r in results:
            flags = ", ".join(r.flags) if r.flags else ""
            print(f"{r.status_code:<8} {r.path:<25} {r.content_length:<10} {flags}")
        sys.exit(0)

    # Launch full interactive TUI
    app = CTFDevToolsApp(initial_url=args.url)
    app.run()

if __name__ == "__main__":
    main()
