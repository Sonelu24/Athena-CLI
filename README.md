# 🦉 Athena-CLI - Purple Team Security Suite

```text
      █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗ 
     ██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
     ███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
     ██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
     ██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
              [ Athena Purple Team Suite v2.0 ]
             -- Offensive & Defensive Security --
```

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-brightgreen.svg)](#features)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Parrot%20%7C%20Ubuntu%20%7C%20Windows-blueviolet.svg)](#installation)

**Athena-CLI** is an ultra-fast, cross-platform terminal security suite built for penetration testers, incident responders, SOC analysts, and security researchers. 

It unifies **14 production-grade security tools** across both offensive (Red Team) and defensive (Blue Team) disciplines into a single high-performance CLI, powered **100% by the Python standard library** with **zero external pip dependencies**.

> 🌐 **Prefer a Graphical Web Dashboard?** Check out [**Athena-Web**](https://github.com/Sonelu24/Athena-Web) - our companion localhost SOC & Recon platform with real-time streaming terminal output, dual red/blue wings, and forensic artifact triage.

![Athena-CLI Live Demo](docs/athenapresentation.gif)

---

## ⚡ Features

- **Zero External Dependencies:** Runs anywhere Python 3.8+ is installed without `pip install` headaches, C-extension compilation errors, or dependency conflicts.
- **Native Kali Linux & Cross-Platform:** Designed for seamless integration into Kali Linux, Parrot OS, Ubuntu, Debian, Fedora, Arch, and Windows (PowerShell / CMD).
- **Vibrant ANSI Visuals:** Auto-detects terminal capabilities, supporting rich glowing purple ANSI visuals, while honoring `NO_COLOR` and non-tty pipelines for script automation.
- **Dual Operating Modes:**
  - **Interactive TUI Menu:** Run `athena` with no arguments to launch an interactive 2-column console selector with built-in `--demo` shortcuts.
  - **Direct Command Router:** Run tools directly via subcommands (e.g. `athena pcap capture.pcapng -o report.json`) with transparent argument pass-through and exit code preservation.
- **Built-in Self-Testing (`--demo`):** Every single tool includes a standalone demo mode generating realistic forensic mock data or safe test requests.

---

## 🛠️ Tool Catalog (14 Subcommands)

### 🔵 Blue Team Subcommands (Defensive & SOC Operations)

| Subcommand | Syntax Instruction | Description | Key Capabilities |
|---|---|---|---|
| `ssh` | `athena ssh <auth.log>` | **SSH & Auth Log Analyzer** | Detects brute-force bursts, invalid users, root logins, sudo privilege escalations, IP geolocation |
| `fim` | `athena fim [init\|check] <dir>` | **File Integrity Monitor** | SHA-256 baselining, detects modified/added/deleted files, permission tampering, recursive directory scans |
| `phish` | `athena phish <email.eml>` | **Phishing Email Analyzer** | SPF/DKIM/DMARC auth alignment, spoofed display names, lookalike domains, obfuscated URLs, malicious attachments |
| `pcap` | `athena pcap <capture.pcap>` | **PCAP Threat Hunter** | Port scans (SYN/FIN/NULL/XMAS), cleartext credential exposure (HTTP POST, FTP, Telnet), DNS tunneling detection |
| `triage` | `athena triage <file.exe\|elf>` | **Malware Triage Scanner** | Entropy calculation (packed/encrypted code), suspicious PE/ELF headers, dangerous API imports, embedded IP/URL strings |
| `ioc` | `athena ioc <file\|text>` | **IOC Extractor & Defanger** | Extracts IPv4, IPv6, MD5, SHA-1, SHA-256, CVEs, emails, defangs malicious URLs (`hxxp[://]`), JSON/CSV export |
| `php2shell-detect` | `athena php2shell-detect <dir>` | **PHP2Shell Detector** | Scans upload directories for polyglot bypasses (`.php5`, `.phtml`, double extensions), hidden eval backdoors |

### 🔴 Red Team Subcommands (Offensive & Reconnaissance)

| Subcommand | Syntax Instruction | Description | Key Capabilities |
|---|---|---|---|
| `map` | `athena map <url> [-m pages]` | **Site & Attack Surface Mapper** | Discovers endpoints, forms, hidden query parameters, robots.txt, sitemaps, emails, sensitive file disclosures |
| `headers` | `athena headers <url>` | **Security Header Scanner** | Evaluates CSP, HSTS, X-Frame-Options, CORS (`*`), Cookie `SameSite`/`Secure`/`HttpOnly`, letter grading (A+ to F) |
| `breach` | `athena breach <password>` | **Password Breach Checker** | k-Anonymity SHA-1 lookup via HIBP API, checks passwords without exposing the cleartext hash over the network |
| `cve` | `athena cve <requirements.txt>` | **CVE Dependency Scanner** | Scans `requirements.txt`, `package.json`, `pom.xml` against OSV.dev and NIST NVD databases for known vulnerabilities |
| `jwt` | `athena jwt <token>` | **JWT Security Auditor** | Tests `alg: none` bypass, weak HMAC secrets brute-force, expired tokens, privilege escalation claims tampering |
| `tls` | `athena tls <domain[:port]>` | **TLS/SSL Certificate Inspector** | X.509 certificate expiry tracking, weak cipher suites (RC4/3DES), deprecated TLS 1.0/1.1, AIA intermediate fetching |
| `php2shell-audit` | `athena php2shell-audit <url>` | **PHP2Shell Exposure Auditor** | Audits web server upload handlers against Apache/Nginx MIME mismatches, `.htaccess` overrides, null-byte exploits |

---

## 🚀 Installation

### Option 1: Native Linux / Kali Linux One-Liner (Recommended)

Run the included installer to set up `/usr/local/bin/athena`:

```bash
git clone https://github.com/Sonelu24/Athena-CLI.git
cd Athena-CLI
chmod +x install.sh
./install.sh
```

Now launch Athena from any directory:

```bash
athena
```

### Option 2: Python Package (`pip`)

Install locally in editable mode:

```bash
pip install -e .
```

### Option 3: Windows (PowerShell / Command Prompt)

On Windows, execute the included `athena.cmd` batch launcher or run directly with Python:

```powershell
# Directly run
python athena.py

# Or use the batch launcher
.\athena.cmd pcap --demo
```

---

## 💻 CLI Usage Examples

### 1. Interactive Menu Mode
Simply run `athena` without arguments:
```bash
$ athena
```
Displays the interactive purple console where you can enter a tool number (`[1]` to `[14]`) and press **Enter** to instantly run its built-in `--demo` or pass custom arguments.

### 2. Direct Subcommand Execution
Pass arguments directly to any tool through Athena:

```bash
# Analyze a packet capture for attacks and credentials
athena pcap /path/to/traffic.pcapng -o /tmp/threat_report.json

# Perform static malware analysis on a suspicious executable
athena triage /path/to/suspect.exe

# Audit website HTTP security headers & SSL posture
athena headers https://example.com

# Audit an application's dependencies for known CVEs
athena cve requirements.txt --min-severity HIGH

# Check a JWT token for vulnerabilities and weak HMAC secrets
athena jwt eyJhbGciOi... --wordlist rockyou.txt
```

### 3. Built-in Demos
Every tool can be tested instantly without needing live test files:

```bash
athena ssh --demo
athena fim --demo
athena phish --demo
athena cve --demo
athena tls --demo
```

### 4. Help & Typo Suggestions
```bash
# Show command reference
athena --help

# Typo auto-correction
$ athena pcapp
[!] Unknown command 'pcapp'. Did you mean 'pcap'?
    Run 'athena --help' to see all commands.
```

---

## ⚖️ Legal & Ethical Disclaimer

**Athena is developed strictly for educational purposes, authorized security research, CTF competitions, and professional penetration testing / SOC operations conducted under explicit, written authorization (e.g., Rules of Engagement contract or explicit mutual consent).**

1. **Authorized Targeting Only:** You may only probe, scan, or analyze systems, networks, applications, or assets that you personally own or for which you have obtained prior written authorization from the owner.
2. **Strictly Prohibited:** Unauthorized network scanning, credential testing, exploitation, or attacking systems without prior legal consent is illegal under local, federal, and international law (including the US Computer Fraud and Abuse Act - CFAA, UK Computer Misuse Act, and equivalent statutes).
3. **Limitation of Liability:** The author (**Alexandru Iosif Mocanu / Sonelu**) assumes NO liability and is NOT responsible for any misuse, damage, data loss, legal consequences, or operational disruption caused by this software. By downloading, executing, or using Athena, you agree to these terms and assume full legal responsibility.

---

## 📄 License & Attribution

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.

**Author:** Alexandru Iosif Mocanu (Sonelu)  
**Copyright:** © 2026 Alexandru Iosif Mocanu (Sonelu). All rights reserved.
