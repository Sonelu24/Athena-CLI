#!/usr/bin/env bash
# Copyright (c) 2026 Alexandru Iosif Mocanu (Sonelu). All rights reserved.
# Athena-CLI Installer for Kali Linux, Parrot OS, Ubuntu, Debian & other Linux distros
set -e

# Purple ANSI Colors
PURPLE='\033[95m'
CYAN='\033[96m'
GREEN='\033[92m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${PURPLE}"
cat << "BANNER"
      █████╗ ████████╗██╗  ██╗███████╗███╗   ██╗ █████╗ 
     ██╔══██╗╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔══██╗
     ███████║   ██║   ███████║█████╗  ██╔██╗ ██║███████║
     ██╔══██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║██╔══██║
     ██║  ██║   ██║   ██║  ██║███████╗██║ ╚████║██║  ██║
     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
              [ Athena Purple Team Suite v2.0 ]
             -- Offensive & Defensive Security --
BANNER
echo -e "${RESET}"

# Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Error: Python 3 is required but not installed.${RESET}"
    echo "    Install it via: sudo apt update && sudo apt install python3"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${CYAN}[*] Detected Python ${PY_VER}${RESET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATHENA_PY="${SCRIPT_DIR}/athena.py"

if [ ! -f "${ATHENA_PY}" ]; then
    echo -e "${RED}[!] Error: Cannot find ${ATHENA_PY}${RESET}"
    exit 1
fi

chmod +x "${ATHENA_PY}"

# Determine target install directory
if [ "$EUID" -eq 0 ]; then
    INSTALL_BIN="/usr/local/bin/athena"
else
    if [ -w "/usr/local/bin" ]; then
        INSTALL_BIN="/usr/local/bin/athena"
    else
        mkdir -p "${HOME}/.local/bin"
        INSTALL_BIN="${HOME}/.local/bin/athena"
        
        # Verify PATH contains ~/.local/bin
        if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
            echo -e "${CYAN}[i] Tip: Add ~/.local/bin to your PATH to run 'athena' from anywhere:${RESET}"
            echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
            echo "    (Add this line to your ~/.bashrc or ~/.zshrc)"
        fi
    fi
fi

# Generate wrapper script
cat << EOF > "${INSTALL_BIN}"
#!/usr/bin/env bash
exec python3 "${ATHENA_PY}" "\$@"
EOF

chmod +x "${INSTALL_BIN}"

echo -e "${GREEN}[+] Successfully installed Athena-CLI executable to: ${BOLD}${INSTALL_BIN}${RESET}"
echo -e "${PURPLE}[*] Launch the interactive menu: ${BOLD}athena${RESET}"
echo -e "${PURPLE}[*] Or run tools directly:      ${BOLD}athena --help${RESET}"
