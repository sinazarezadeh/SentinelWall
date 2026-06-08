#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "\033[0;34m[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root"
fi

echo -e "${BOLD}${RED}SentinelWall Uninstall${NC}"
echo ""
echo "This will remove:"
echo "  - SentinelWall binaries (/usr/local/bin/sentineld, sentinel, sentinel-tui)"
echo "  - systemd service unit"
echo "  - System user 'sentinel'"
echo ""
read -r -p "Also remove configuration and data? [y/N] " REMOVE_DATA

echo ""
read -r -p "Are you sure you want to uninstall SentinelWall? [y/N] " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

# Stop and disable service
if systemctl is-active --quiet sentineld 2>/dev/null; then
    info "Stopping sentineld..."
    systemctl stop sentineld
    success "Service stopped"
fi

if systemctl is-enabled --quiet sentineld 2>/dev/null; then
    info "Disabling sentineld..."
    systemctl disable sentineld
fi

# Flush nftables rules
if command -v nft &>/dev/null; then
    info "Flushing SentinelWall nftables rules..."
    nft delete table inet sentinel 2>/dev/null || true
    success "nftables rules flushed"
fi

# Remove binaries
for bin in sentineld sentinel sentinel-tui; do
    if [ -f "/usr/local/bin/$bin" ]; then
        rm -f "/usr/local/bin/$bin"
        info "Removed /usr/local/bin/$bin"
    fi
done

# Remove systemd unit
if [ -f /etc/systemd/system/sentineld.service ]; then
    rm -f /etc/systemd/system/sentineld.service
    systemctl daemon-reload
    info "Removed systemd unit"
fi

# Optionally remove data
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    rm -rf /etc/sentinelwall
    rm -rf /var/lib/sentinelwall
    rm -rf /var/log/sentinelwall
    success "Configuration and data removed"
fi

# Remove system user
if id sentinel &>/dev/null; then
    userdel sentinel 2>/dev/null || true
    success "User 'sentinel' removed"
fi

echo ""
success "SentinelWall has been uninstalled."
