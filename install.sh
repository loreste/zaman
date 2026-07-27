#!/bin/bash
# Zaman — universal installer for Linux (Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky)
# Usage: curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo bash
#   or:  sudo bash install.sh
#
# Options (env vars):
#   ZAMAN_DB=sqlite|postgres|clickhouse   (default: sqlite)
#   ZAMAN_SKIP_DB=1                       (skip database setup)
#   ZAMAN_INSTALL_DIR=/opt/zaman          (default)
#   ZAMAN_BRANCH=main                     (git branch)

set -euo pipefail

INSTALL_DIR="${ZAMAN_INSTALL_DIR:-/opt/zaman}"
DB_CHOICE="${ZAMAN_DB:-sqlite}"
BRANCH="${ZAMAN_BRANCH:-main}"
CONF_DIR="/etc/zaman"
DATA_DIR="${INSTALL_DIR}/data"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[zaman]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*"; exit 1; }

# ── Detect distro ──
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID}"
        DISTRO_FAMILY="${ID_LIKE:-${ID}}"
    elif [ -f /etc/redhat-release ]; then
        DISTRO_ID="rhel"
        DISTRO_FAMILY="rhel"
    else
        err "Unsupported distribution. Requires Debian/Ubuntu or RHEL/CentOS/Fedora/Rocky."
    fi

    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop) PKG_MGR="apt" ;;
        centos|rhel|rocky|almalinux|fedora|ol) PKG_MGR="yum" ;;
        *)
            case "$DISTRO_FAMILY" in
                *debian*|*ubuntu*) PKG_MGR="apt" ;;
                *rhel*|*fedora*|*centos*) PKG_MGR="yum" ;;
                *) err "Unsupported distro: ${DISTRO_ID} (${DISTRO_FAMILY})" ;;
            esac
            ;;
    esac

    log "Detected: ${DISTRO_ID} (${PKG_MGR})"
}

# ── Install system packages ──
install_deps() {
    log "Installing system dependencies..."
    if [ "$PKG_MGR" = "apt" ]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq curl git make clang gcc python3 openssl ca-certificates sqlite3 >/dev/null
    else
        yum install -y -q curl git make clang gcc python3 openssl ca-certificates sqlite >/dev/null 2>&1 || \
        dnf install -y -q curl git make clang gcc python3 openssl ca-certificates sqlite >/dev/null 2>&1
    fi
}

# ── Install Mako ──
install_mako() {
    if command -v mako >/dev/null 2>&1; then
        log "Mako already installed: $(mako version 2>/dev/null | head -1)"
        return
    fi
    log "Installing Mako..."
    mkdir -p /usr/local/bin
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MAKO_ARCH="amd64" ;;
        aarch64|arm64) MAKO_ARCH="arm64" ;;
        *) err "Unsupported architecture: $ARCH" ;;
    esac
    curl -fsSL "https://mako-lang.dev/dl/mako-linux-${MAKO_ARCH}" -o /usr/local/bin/mako
    chmod +x /usr/local/bin/mako
    log "Mako installed: $(mako version 2>/dev/null | head -1)"
}

# ── Install Weft ──
install_weft() {
    if command -v weft >/dev/null 2>&1; then
        log "Weft already installed: $(weft version 2>/dev/null | head -1)"
        return
    fi
    log "Installing Weft..."
    mkdir -p /usr/local/bin
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) WEFT_ARCH="amd64" ;;
        aarch64|arm64) WEFT_ARCH="arm64" ;;
        *) err "Unsupported architecture: $ARCH" ;;
    esac
    curl -fsSL "https://weft.dev/dl/weft-linux-${WEFT_ARCH}" -o /usr/local/bin/weft
    chmod +x /usr/local/bin/weft
    log "Weft installed: $(weft version 2>/dev/null | head -1)"
}

# ── Install database ──
install_database() {
    if [ "${ZAMAN_SKIP_DB:-0}" = "1" ]; then
        warn "Skipping database setup (ZAMAN_SKIP_DB=1)"
        return
    fi

    case "$DB_CHOICE" in
        sqlite)
            log "Using SQLite (no additional setup needed)"
            ;;
        postgres|postgresql)
            log "Installing PostgreSQL..."
            if [ "$PKG_MGR" = "apt" ]; then
                apt-get install -y -qq postgresql postgresql-client >/dev/null
            else
                yum install -y -q postgresql-server postgresql >/dev/null 2>&1 || \
                dnf install -y -q postgresql-server postgresql >/dev/null 2>&1
                postgresql-setup --initdb 2>/dev/null || true
            fi
            systemctl enable --now postgresql 2>/dev/null || true
            # Create database and user
            sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='zaman'" | grep -q 1 || {
                sudo -u postgres createuser --no-password zaman 2>/dev/null || true
                sudo -u postgres createdb -O zaman zaman 2>/dev/null || true
                log "Created PostgreSQL database 'zaman'"
            }
            DB_CHOICE="postgres"
            ;;
        clickhouse|ch)
            log "Installing ClickHouse..."
            if [ "$PKG_MGR" = "apt" ]; then
                curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg 2>/dev/null || true
                echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" > /etc/apt/sources.list.d/clickhouse.list
                apt-get update -qq
                apt-get install -y -qq clickhouse-server clickhouse-client >/dev/null
            else
                yum install -y -q yum-utils >/dev/null 2>&1 || true
                yum-config-manager --add-repo https://packages.clickhouse.com/rpm/clickhouse.repo 2>/dev/null || true
                yum install -y -q clickhouse-server clickhouse-client >/dev/null 2>&1 || \
                dnf install -y -q clickhouse-server clickhouse-client >/dev/null 2>&1
            fi
            systemctl enable --now clickhouse-server 2>/dev/null || true
            sleep 2
            clickhouse-client --query "CREATE DATABASE IF NOT EXISTS zaman" 2>/dev/null || true
            DB_CHOICE="clickhouse"
            log "ClickHouse ready"
            ;;
        *)
            err "Unknown database: $DB_CHOICE. Use: sqlite, postgres, or clickhouse"
            ;;
    esac
}

# ── Install Zaman ──
install_zaman() {
    log "Installing Zaman to ${INSTALL_DIR}..."

    # Create user
    id -u zaman >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" -m zaman

    # Clone or update
    if [ -d "${INSTALL_DIR}/.git" ]; then
        log "Updating existing installation..."
        cd "$INSTALL_DIR"
        git pull origin "$BRANCH" --ff-only 2>/dev/null || true
    else
        mkdir -p "$INSTALL_DIR"
        git clone --depth 1 --branch "$BRANCH" https://github.com/loreste/zaman.git "$INSTALL_DIR" 2>/dev/null || {
            # Fallback: copy from current directory if running from repo
            if [ -f "$(dirname "$0")/core/main.mko" ]; then
                cp -r "$(dirname "$0")"/* "$INSTALL_DIR/" 2>/dev/null || true
                cp -r "$(dirname "$0")"/.git "$INSTALL_DIR/" 2>/dev/null || true
            else
                err "Could not clone repository. Install git and try again."
            fi
        }
    fi

    cd "$INSTALL_DIR"

    # Build
    log "Building zaman-core..."
    mkdir -p bin
    mako build --release core/main.mko -o bin/zaman-core
    log "Built: bin/zaman-core"

    # Create directories
    mkdir -p "$DATA_DIR" "$CONF_DIR"

    # Set ownership
    chown -R zaman:zaman "$INSTALL_DIR"
    chmod 750 "$DATA_DIR"

    # Install systemd units
    cp deploy/zaman-core.service /etc/systemd/system/
    cp deploy/zaman-web.service /etc/systemd/system/

    # Write env files
    if [ ! -f "$CONF_DIR/core.env" ]; then
        cat > "$CONF_DIR/core.env" << COREENV
# Zaman core configuration
ZAMAN_SIP_HOST=0.0.0.0
ZAMAN_DB=${DATA_DIR}/zaman.db
ZAMAN_PROBE=0
# ZAMAN_API_KEY=
# ZAMAN_HEP_TCP=0
# ZAMAN_HEP_TLS=0
COREENV

        # Database-specific config
        case "$DB_CHOICE" in
            postgres)
                cat >> "$CONF_DIR/core.env" << PGENV
ZAMAN_DB_DRIVER=postgres
ZAMAN_DB_DSN=host=/var/run/postgresql dbname=zaman user=zaman sslmode=disable
PGENV
                ;;
            clickhouse)
                cat >> "$CONF_DIR/core.env" << CHENV
ZAMAN_DB_DRIVER=clickhouse
ZAMAN_CH_URL=http://127.0.0.1:8123
ZAMAN_CH_DB=zaman
CHENV
                ;;
        esac
    fi

    if [ ! -f "$CONF_DIR/web.env" ]; then
        cat > "$CONF_DIR/web.env" << WEBENV
# Zaman dashboard configuration
ZAMAN_CORE=http://127.0.0.1:9090
ZAMAN_DATA_DIR=${DATA_DIR}
# ZAMAN_AUTH=0
# ZAMAN_DASHBOARD_ALLOW_IPS=
WEBENV
    fi

    systemctl daemon-reload
}

# ── Start services ──
start_services() {
    log "Starting Zaman services..."
    systemctl enable --now zaman-core
    sleep 2
    systemctl enable --now zaman-web
    sleep 2

    # Health check
    if curl -fs http://127.0.0.1:9090/api/health >/dev/null 2>&1; then
        log "Core is healthy"
    else
        warn "Core health check failed — check: journalctl -u zaman-core"
    fi

    if curl -fs http://127.0.0.1:3000/login >/dev/null 2>&1; then
        log "Dashboard is running"
    else
        warn "Dashboard check failed — check: journalctl -u zaman-web"
    fi
}

# ── Print summary ──
print_summary() {
    # Get the admin password if this is a fresh install
    ADMIN_PW=$(journalctl -u zaman-web --no-pager -n 50 2>/dev/null | grep 'password:' | tail -1 | sed 's/.*password: //;s/ .*//' || echo "")

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}Zaman installed successfully${NC}                            ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Dashboard:  ${GREEN}http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'):3000${NC}"
    echo -e "${CYAN}║${NC}  Core API:   http://127.0.0.1:9090/api/health            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  SIP:        udp/5060                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  HEP:        udp/9060                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Database:   ${DB_CHOICE}                                ${CYAN}║${NC}"
    if [ -n "$ADMIN_PW" ]; then
    echo -e "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Login:      admin / ${YELLOW}${ADMIN_PW}${NC}"
    fi
    echo -e "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Config:     /etc/zaman/core.env                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}               /etc/zaman/web.env                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Logs:       journalctl -u zaman-core                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}               journalctl -u zaman-web                     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Data:       ${DATA_DIR}                                 ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Main ──
main() {
    echo ""
    echo -e "${CYAN}Zaman — SIP monitoring installer${NC}"
    echo ""

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        err "Run as root: sudo bash install.sh"
    fi

    # Interactive database selection if not set
    if [ -z "${ZAMAN_DB:-}" ]; then
        echo "Select database backend:"
        echo ""
        echo "  1) SQLite    — zero config, single file (recommended for most)"
        echo "  2) PostgreSQL — production relational database"
        echo "  3) ClickHouse — columnar, millions of calls/day"
        echo ""
        read -rp "Choice [1]: " db_num
        case "${db_num:-1}" in
            1|"") DB_CHOICE="sqlite" ;;
            2) DB_CHOICE="postgres" ;;
            3) DB_CHOICE="clickhouse" ;;
            *) DB_CHOICE="sqlite" ;;
        esac
    fi

    log "Database: ${DB_CHOICE}"
    echo ""

    detect_distro
    install_deps
    install_mako
    install_weft
    install_database
    install_zaman
    start_services
    print_summary
}

main "$@"
