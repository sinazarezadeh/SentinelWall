#!/usr/bin/env bash
set -euo pipefail

# SentinelWall Installation Script
# Usage: curl -sSL https://raw.githubusercontent.com/sinazarezadeh/SentinelWall/main/scripts/install.sh | sudo bash

REPO="sinazarezadeh/SentinelWall"
REPO_URL="https://github.com/${REPO}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sentinelwall"
DATA_DIR="/var/lib/sentinelwall"
LOG_DIR="/var/log/sentinelwall"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_USER="sentinel"
SERVICE_GROUP="sentinel"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $*" >&2; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *) error "Unsupported architecture: $arch" ;;
    esac
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root. Try: sudo bash $0"
    fi
}

check_systemd() {
    if ! command -v systemctl &>/dev/null; then
        error "systemd is required but not found"
    fi
}

check_nftables() {
    if ! command -v nft &>/dev/null; then
        info "Installing nftables..."
        local distro
        distro=$(detect_distro)
        case "$distro" in
            ubuntu|debian)
                apt-get install -y nftables ;;
            fedora|rhel|centos|rocky|almalinux)
                dnf install -y nftables ;;
            arch)
                pacman -S --noconfirm nftables ;;
            *)
                error "Cannot install nftables: unknown distro '$distro'. Please install nftables manually." ;;
        esac
    fi
    success "nftables available"
}

get_latest_version() {
    local tag
    tag=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name": "([^"]+)".*/\1/')
    echo "$tag"
}

install_rust() {
    if ! command -v cargo &>/dev/null; then
        info "Installing Rust toolchain..."
        curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
        success "Rust installed"
    else
        info "Rust already installed: $(rustc --version)"
    fi
}

install_build_deps() {
    info "Installing build dependencies..."
    local distro
    distro=$(detect_distro)
    case "$distro" in
        ubuntu|debian)
            apt-get install -y build-essential pkg-config libssl-dev git curl nftables ;;
        fedora|rhel|centos|rocky|almalinux)
            dnf install -y gcc openssl-devel pkgconfig git curl nftables ;;
        arch)
            pacman -S --noconfirm base-devel openssl git curl nftables ;;
        *)
            warn "Unknown distro — ensure gcc, openssl-dev, pkg-config, git are installed" ;;
    esac
    success "Build dependencies installed"
}

build_from_source() {
    local tmpdir
    tmpdir=$(mktemp -d)

    info "Cloning SentinelWall from ${REPO_URL}..."
    git clone --depth=1 "${REPO_URL}.git" "$tmpdir/src" \
        || error "git clone failed. Check your network connection and try again."

    info "Building (this takes a few minutes)..."
    (
        cd "$tmpdir/src"
        # shellcheck source=/dev/null
        [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
        cargo build --release \
            --bin sentineld \
            --bin sentinel \
            --bin sentinel-tui
    ) >&2 || error "Build failed. Run with RUST_LOG=error for details."

    mkdir -p "$tmpdir/dist"
    cp "$tmpdir/src/target/release/sentineld"         "$tmpdir/dist/"
    cp "$tmpdir/src/target/release/sentinel"          "$tmpdir/dist/"
    cp "$tmpdir/src/target/release/sentinel-tui"      "$tmpdir/dist/"
    cp "$tmpdir/src/configs/sentinelwall.toml"        "$tmpdir/dist/"
    cp "$tmpdir/src/deploy/systemd/sentineld.service" "$tmpdir/dist/"

    # Only stdout: the dist path (captured by caller)
    echo "$tmpdir/dist"
}

download_release() {
    local version="$1"
    local target="$2"
    local url="https://github.com/${REPO}/releases/download/${version}/sentinelwall-${version}-${target}.tar.gz"
    local tmpdir
    tmpdir=$(mktemp -d)

    info "Downloading SentinelWall ${version} (${target})..."
    curl -sSfL "$url" | tar -xz -C "$tmpdir" || error "Download failed: ${url}"

    local checksum_url="${url}.sha256"
    if curl -sSfL "$checksum_url" -o "$tmpdir/checksum.sha256" 2>/dev/null; then
        (cd "$tmpdir" && sha256sum -c checksum.sha256 --quiet) || error "Checksum verification failed"
        success "Checksum verified"
    fi

    echo "$tmpdir"
}

create_user() {
    if ! id "$SERVICE_USER" &>/dev/null; then
        info "Creating system user '${SERVICE_USER}'..."
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --comment "SentinelWall daemon" "$SERVICE_USER"
        success "User '${SERVICE_USER}' created"
    else
        info "User '${SERVICE_USER}' already exists"
    fi
}

install_binaries() {
    local srcdir="$1"
    info "Installing binaries to ${INSTALL_DIR}..."
    install -o root -g root -m 755 "$srcdir/sentineld"    "$INSTALL_DIR/sentineld"
    install -o root -g root -m 755 "$srcdir/sentinel"     "$INSTALL_DIR/sentinel"
    install -o root -g root -m 755 "$srcdir/sentinel-tui" "$INSTALL_DIR/sentinel-tui"

    if command -v setcap &>/dev/null; then
        setcap 'cap_net_admin,cap_net_raw+eip' "$INSTALL_DIR/sentineld"
        success "Network capabilities granted"
    else
        warn "setcap not found — daemon will need to run as root"
    fi

    success "Binaries installed"
}

install_config() {
    local srcdir="$1"
    info "Setting up configuration..."

    mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/rules.d"

    if [ ! -f "$CONFIG_DIR/sentinelwall.toml" ]; then
        install -o root -g "$SERVICE_GROUP" -m 640 \
            "$srcdir/sentinelwall.toml" "$CONFIG_DIR/sentinelwall.toml"
        success "Default config installed at ${CONFIG_DIR}/sentinelwall.toml"
    else
        warn "Config already exists at ${CONFIG_DIR}/sentinelwall.toml — not overwriting"
    fi

    mkdir -p "$DATA_DIR" "$LOG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"
    chmod 750 "$DATA_DIR" "$LOG_DIR"

    success "Directories configured"
}

install_systemd() {
    local srcdir="$1"
    info "Installing systemd service..."
    install -o root -g root -m 644 \
        "$srcdir/sentineld.service" "$SYSTEMD_DIR/sentineld.service"
    systemctl daemon-reload
    success "systemd service installed"
}

enable_service() {
    info "Enabling and starting sentineld..."
    systemctl enable sentineld
    systemctl start sentineld

    local retries=0
    while [ $retries -lt 10 ]; do
        if sentinel status &>/dev/null; then
            success "SentinelWall is running!"
            return 0
        fi
        sleep 1
        ((retries++))
    done
    warn "Service started but health check timed out. Check: journalctl -u sentineld"
}

print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
   ____            _   _            _  _    _    _____       _ _
  / ___|  ___ _ __| |_(_)_ __   ___| || |  | |  |  _  \    | | |
  \___ \ / _ \ '_ \  _| | '_ \ / _ \ || |_ | |  | | | |__  | | |
   ___) |  __/ | | | |_| | | | |  __/|__   _| |  | |/ / __ | | |
  |____/ \___|_| |_|\__|_|_| |_|\___|   |_|  \___/\____|__||_|_|

         Next-Generation Linux Firewall & IPS
EOF
    echo -e "${NC}"
}

print_summary() {
    echo ""
    echo -e "${BOLD}Installation complete!${NC}"
    echo ""
    echo "Quick start:"
    echo "  sentinel status                — Check firewall status"
    echo "  sentinel profile apply server  — Apply server profile"
    echo "  sentinel list                  — List active rules"
    echo "  sentinel-tui                   — Interactive TUI"
    echo ""
    echo "Configuration: ${CONFIG_DIR}/sentinelwall.toml"
    echo "Logs:          journalctl -u sentineld -f"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Change the admin password:${NC}"
    echo "  SENTINEL_ADMIN_PASSWORD=<newpass> systemctl restart sentineld"
}

main() {
    print_banner
    check_root
    check_systemd
    check_nftables

    local srcdir version

    local tmproot
    tmproot=$(mktemp -d)
    trap "rm -rf ${tmproot}" EXIT

    # Explicit version passed as argument
    if [ -n "${1:-}" ]; then
        version="$1"
        local target
        target=$(detect_arch)
        srcdir=$(download_release "$version" "$target")

    else
        # Try to get a prebuilt release
        info "Checking for prebuilt releases..."
        version=$(get_latest_version)

        if [ -n "$version" ]; then
            info "Found release: ${version}"
            local target
            target=$(detect_arch)
            srcdir=$(download_release "$version" "$target")
        else
            # No releases yet — build from source
            warn "No prebuilt releases found. Building from source..."
            install_build_deps
            install_rust
            srcdir=$(build_from_source)
        fi
    fi

    create_user
    install_binaries "$srcdir"
    install_config "$srcdir"
    install_systemd "$srcdir"
    enable_service

    print_summary
}

main "$@"
