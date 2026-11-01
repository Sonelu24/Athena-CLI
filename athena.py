#!/usr/bin/env python3
# Copyright (c) 2026 Alexandru Iosif Mocanu (Sonelu). All rights reserved.
"""
Athena-CLI v2.0 - Purple Team Security Suite (Offensive & Defensive Security)

Unified command-line launcher for the Athena Blue Team (defensive / SOC) and
Red Team (offensive / recon) tools.

Usage:
    athena                      Interactive menu
    athena <command> [args]     Run a tool directly, forwarding all arguments
    athena list                 Show the command table with instructions
    athena --help | --version

For education and authorized security testing only.
"""

import difflib
import os
import shlex
import subprocess
import sys
from pathlib import Path

VERSION = "2.0"
BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "tools"

# --------------------------------------------------------------------------- colours


def _enable_windows_ansi() -> bool:
    """Turns on ANSI escape processing in the Windows console. Returns True on success."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _colours_supported() -> bool:
    """Colours are used only on an interactive terminal and when NO_COLOR is not set."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_ansi()
    return True


if _colours_supported():
    PURPLE = "\033[95m"
    DARK_PURPLE = "\033[35m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
else:
    PURPLE = DARK_PURPLE = CYAN = BLUE = RED = BOLD = DIM = RESET = ""

# --------------------------------------------------------------------------- banner
BANNER_ART = r"""
      █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗ 
     ██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
     ███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
     ██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
     ██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
              [ Athena Purple Team Suite v2.0 ]
             -- Offensive & Defensive Security --"""

LEGAL_LINE = "        For education & authorized security testing only."

# --------------------------------------------------------------------------- command registry
# (command, team, script path relative to tools/, syntax/instructions, short description, example argument)
COMMANDS = [
    (
        "ssh",
        "blue",
        "blue/log_analyzer.py",
        "athena ssh <auth.log>",
        "SSH & Auth Log Analyzer (brute-force bursts, invalid users, root escalation)",
        "/var/log/auth.log",
    ),
    (
        "fim",
        "blue",
        "blue/fim.py",
        "athena fim [init|check] <dir>",
        "File Integrity Monitor (SHA-256 integrity baseline & unauthorized changes)",
        "check /etc",
    ),
    (
        "phish",
        "blue",
        "blue/phishing_analyzer.py",
        "athena phish <email.eml>",
        "Phishing Email Analyzer (SPF/DKIM/DMARC, lookalike domains, obfuscated URLs)",
        "suspicious_invoice.eml",
    ),
    (
        "pcap",
        "blue",
        "blue/pcap_hunter.py",
        "athena pcap <capture.pcap>",
        "PCAP Threat Hunter (port scans, cleartext credentials, DNS covert tunneling)",
        "traffic.pcapng -o report.json",
    ),
    (
        "triage",
        "blue",
        "blue/malware_triage.py",
        "athena triage <file.exe|elf>",
        "Malware Triage Scanner (Shannon entropy, suspicious imports, PE/ELF headers)",
        "suspect_sample.exe",
    ),
    (
        "ioc",
        "blue",
        "blue/ioc_extractor.py",
        "athena ioc <file|text>",
        "IOC Extractor & Defanger (IPs, URLs, MD5/SHA-256, CVEs, export JSON/CSV)",
        "threat_intel_dump.txt -o iocs.json",
    ),
    (
        "php2shell-detect",
        "blue",
        "blue/php2shell_detector.py",
        "athena php2shell-detect <dir>",
        "PHP2Shell Detector (scan uploads for polyglot web shells & PHP backdoors)",
        "/var/www/html/uploads",
    ),
    (
        "map",
        "red",
        "red/site_mapper.py",
        "athena map <url> [-m pages]",
        "Website Crawler & Site Mapper (directory tree, JS endpoints & leaked secrets)",
        "https://example.com -m 30",
    ),
    (
        "headers",
        "red",
        "red/header_scanner.py",
        "athena headers <url>",
        "Security Header Scanner (CSP, HSTS preload, CORS misconfigs, letter grade A+..F)",
        "https://example.com",
    ),
    (
        "breach",
        "red",
        "red/breach_checker.py",
        "athena breach <password>",
        "Password Breach Checker (k-Anonymity SHA-1 lookup via HIBP API)",
        "P@ssw0rd2026",
    ),
    (
        "cve",
        "red",
        "red/cve_scanner.py",
        "athena cve <requirements.txt>",
        "CVE Dependency Scanner (audit Python/JS dependencies via OSV.dev database)",
        "requirements.txt --min-severity HIGH",
    ),
    (
        "jwt",
        "red",
        "red/jwt_auditor.py",
        "athena jwt <token>",
        "JWT Security Auditor (alg:none bypass, secret brute-force & claims tampering)",
        "eyJhbGciOi... --wordlist rockyou.txt",
    ),
    (
        "tls",
        "red",
        "red/tls_inspector.py",
        "athena tls <domain[:port]>",
        "TLS & Certificate Inspector (expiry, deprecated ciphers, SANs & AIA chain)",
        "example.com --enum-ciphers",
    ),
    (
        "php2shell-audit",
        "red",
        "red/php2shell_auditor.py",
        "athena php2shell-audit <url>",
        "PHP2Shell Exposure Auditor (audit web upload forms against MIME/extension bypass)",
        "https://example.com/upload.php",
    ),
]
COMMAND_MAP = {name: (team, script, syntax, desc, example) for name, team, script, syntax, desc, example in COMMANDS}
BUILTINS = ["help", "list", "web"]


# --------------------------------------------------------------------------- output helpers
def print_banner() -> None:
    print(f"{PURPLE}{BANNER_ART}{RESET}")
    print(f"{DIM}{LEGAL_LINE}{RESET}\n")


def print_command_table() -> None:
    for team, colour, title in (
        ("blue", BLUE, "DEFENSIVE (Blue Team)"),
        ("red", RED, "OFFENSIVE (Red Team)"),
    ):
        print(f"  {colour}{BOLD}{title}{RESET}")
        for name, t, _script, syntax, desc, _example in COMMANDS:
            if t == team:
                print(f"    {colour}{name:<17}{RESET} {CYAN}{syntax:<34}{RESET} {desc}")
        print()


def print_help() -> None:
    print_banner()
    print(f"{BOLD}USAGE{RESET}")
    print("  athena                       Open the interactive menu")
    print("  athena <command> [args]      Run a tool (all arguments are passed through)")
    print("  athena <command> --help      Show that specific tool's complete options")
    print("  athena list                  Show the command & instructions table")
    print("  athena --version             Show version info\n")
    print(f"{BOLD}COMMANDS & INSTRUCTIONS{RESET}")
    print_command_table()
    print(f"  {PURPLE}{BOLD}OTHER{RESET}")
    print(f"    {PURPLE}{'web':<17}{RESET} {'athena web':<34} Web dashboard (provided by Athena-Web)\n")
    print(f"{BOLD}QUICK EXAMPLES{RESET}")
    print("  athena pcap capture.pcapng -o report.json")
    print("  athena map https://example.com -m 30")
    print("  athena tls example.com --enum-ciphers")
    print("  athena cve requirements.txt")
    print("  athena pcap --demo     (every tool supports --demo!)\n")


# --------------------------------------------------------------------------- dispatcher
def run_tool(command: str, args: list[str]) -> int:
    """Runs a tool script with the current Python interpreter and returns its exit code."""
    script = COMMAND_MAP[command][1]
    script_path = TOOLS_DIR / script
    if not script_path.is_file():
        print(f"{RED}[!] Tool script not found: {script_path}{RESET}", file=sys.stderr)
        return 1

    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        completed = subprocess.run([sys.executable, str(script_path), *args], env=env)
    except KeyboardInterrupt:
        print(f"\n{DIM}[*] Interrupted.{RESET}")
        return 130
    return completed.returncode


def suggest(command: str) -> str | None:
    matches = difflib.get_close_matches(command, list(COMMAND_MAP) + BUILTINS, n=1, cutoff=0.6)
    return matches[0] if matches else None


def split_args(raw: str) -> list[str]:
    """Splits a user-typed argument string, keeping Windows backslash paths intact."""
    if os.name == "nt":
        parts = shlex.split(raw, posix=False)
        return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]
    return shlex.split(raw)


# --------------------------------------------------------------------------- interactive menu
def print_menu() -> None:
    blue = [c for c in COMMANDS if c[1] == "blue"]
    red = [c for c in COMMANDS if c[1] == "red"]
    col_width = 46
    print(f"  {BLUE}{BOLD}{'DEFENSIVE (Blue Team)':<{col_width}}{RESET}{RED}{BOLD}OFFENSIVE (Red Team){RESET}")
    for i in range(max(len(blue), len(red))):
        left = right = ""
        left_plain = ""
        if i < len(blue):
            name, _t, _s, syntax, _desc, _ex = blue[i]
            param = syntax.replace(f"athena {name}", "").strip()
            left_plain = f"[{i + 1:>2}] {name:<16} {param}"
            left = f"{BLUE}[{i + 1:>2}]{RESET} {BOLD}{name:<16}{RESET} {DIM}{param}{RESET}"
        if i < len(red):
            name, _t, _s, syntax, _desc, _ex = red[i]
            param = syntax.replace(f"athena {name}", "").strip()
            right = f"{RED}[{i + 1 + len(blue):>2}]{RESET} {BOLD}{name:<16}{RESET} {DIM}{param}{RESET}"
        padding = " " * max(2, (col_width - len(left_plain)))
        print(f"  {left}{padding}{right}")
    print(f"\n  {PURPLE}[h]{RESET} Help   {PURPLE}[q]{RESET} Quit\n")


def interactive_menu() -> int:
    print_banner()
    while True:
        print_menu()
        try:
            choice = input(f"{PURPLE}athena>{RESET} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{DIM}Goodbye.{RESET}")
            return 0

        if choice in ("q", "quit", "exit"):
            print(f"{DIM}Goodbye.{RESET}")
            return 0
        if choice in ("h", "help"):
            print_help()
            continue
        if choice in ("l", "list"):
            print_command_table()
            continue
        if not choice:
            continue

        command = None
        if choice.isdigit() and 1 <= int(choice) <= len(COMMANDS):
            command = COMMANDS[int(choice) - 1][0]
        elif choice in COMMAND_MAP:
            command = choice

        if command is None:
            hint = suggest(choice)
            extra = f" Did you mean '{hint}'?" if hint else ""
            print(f"{RED}[!] Unknown choice '{choice}'.{extra}{RESET}\n")
            continue

        syntax = COMMAND_MAP[command][2]
        desc = COMMAND_MAP[command][3]
        example = COMMAND_MAP[command][4]

        print(f"\n{PURPLE}==> {BOLD}[{command.upper()}]{RESET} {desc}")
        print(f"    {DIM}Instruction : {RESET}{CYAN}{syntax}{RESET}")
        print(f"    {DIM}Example     : {RESET}athena {command} {example}")
        print(f"    {DIM}Demo mode   : {RESET}Press {BOLD}[Enter]{RESET} to run with built-in mock data (--demo)")

        try:
            raw = input(f"    {PURPLE}Arguments >{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            continue

        if raw.lower() in ("q", "quit", "cancel", "back"):
            print(f"{DIM}[*] Cancelled.{RESET}\n")
            continue

        try:
            args = split_args(raw) if raw else ["--demo"]
        except ValueError as exc:
            print(f"{RED}[!] Could not parse arguments: {exc}{RESET}\n")
            continue

        code = run_tool(command, args)
        print(f"\n{DIM}[*] '{command}' finished with exit code {code}.{RESET}\n")


# --------------------------------------------------------------------------- entry point
def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        return interactive_menu()

    command, rest = argv[0], argv[1:]

    if command in ("-h", "--help", "help"):
        print_help()
        return 0
    if command in ("-V", "--version", "version"):
        print(f"Athena-CLI v{VERSION}")
        return 0
    if command == "list":
        print_command_table()
        return 0
    if command == "web":
        print(f"{PURPLE}[*] The Athena web dashboard is provided by the separate Athena-Web repository.{RESET}")
        return 0
    if command in COMMAND_MAP:
        return run_tool(command, rest)

    hint = suggest(command)
    extra = f" Did you mean '{hint}'?" if hint else ""
    print(f"{RED}[!] Unknown command '{command}'.{extra}{RESET}", file=sys.stderr)
    print("    Run 'athena --help' to see all commands.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
