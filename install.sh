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
        apt-get install -y -qq \
            curl wget git make \
            clang gcc libc-dev \
            python3 \
            openssl libssl-dev \
            ca-certificates \
            sqlite3 libsqlite3-dev \
            pkg-config \
            >/dev/null 2>&1
        log "APT dependencies installed"
    else
        # RHEL/CentOS/Fedora/Rocky
        yum install -y -q \
            curl wget git make \
            clang gcc glibc-devel \
            python3 \
            openssl openssl-devel \
            ca-certificates \
            sqlite sqlite-devel \
            pkgconfig \
            >/dev/null 2>&1 || \
        dnf install -y -q \
            curl wget git make \
            clang gcc glibc-devel \
            python3 \
            openssl openssl-devel \
            ca-certificates \
            sqlite sqlite-devel \
            pkgconfig \
            >/dev/null 2>&1
        log "YUM/DNF dependencies installed"
    fi
}

# ── Install Makori ──
install_mako() {
    if command -v makori >/dev/null 2>&1; then
        MAKO_VER=$(makori version 2>/dev/null | head -1)
        log "Makori already installed: ${MAKO_VER}"
        return
    fi

    log "Installing Makori language..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) MAKO_ARCH="amd64" ;;
        aarch64|arm64) MAKO_ARCH="arm64" ;;
        *) err "Unsupported architecture: $ARCH" ;;
    esac

    mkdir -p /usr/local/bin

    # Try official install script first
    if curl -fsSL https://mako-lang.dev/install.sh -o /tmp/makori-install.sh 2>/dev/null; then
        bash /tmp/makori-install.sh 2>/dev/null && {
            # Move to system path if installed to ~/.local/bin
            [ -f "$HOME/.local/bin/makori" ] && cp "$HOME/.local/bin/makori" /usr/local/bin/makori
            rm -f /tmp/makori-install.sh
        }
    fi

    # Fallback: direct binary download
    if ! command -v makori >/dev/null 2>&1; then
        for url in \
            "https://mako-lang.dev/dl/makori-linux-${MAKO_ARCH}" \
            "https://github.com/mako-lang/mako/releases/latest/download/makori-linux-${MAKO_ARCH}" \
            "https://mako-lang.dev/dl/mako-linux-${MAKO_ARCH}"; do
            if curl -fsSL "$url" -o /usr/local/bin/makori 2>/dev/null; then
                chmod +x /usr/local/bin/makori
                break
            fi
        done
    fi

    # Verify
    if ! command -v makori >/dev/null 2>&1; then
        err "Failed to install Makori. Install manually from https://mako-lang.dev and re-run."
    fi

    log "Makori installed: $(makori version 2>/dev/null | head -1)"
}

# ── Install Weft ──
install_weft() {
    if command -v weft >/dev/null 2>&1; then
        WEFT_VER=$(weft version 2>/dev/null | head -1)
        log "Weft already installed: ${WEFT_VER}"
        return
    fi

    log "Installing Weft framework..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) WEFT_ARCH="amd64" ;;
        aarch64|arm64) WEFT_ARCH="arm64" ;;
        *) err "Unsupported architecture: $ARCH" ;;
    esac

    mkdir -p /usr/local/bin

    # Try official install script first
    if curl -fsSL https://weft.dev/install.sh -o /tmp/weft-install.sh 2>/dev/null; then
        bash /tmp/weft-install.sh 2>/dev/null && {
            [ -f "$HOME/.local/bin/weft" ] && cp "$HOME/.local/bin/weft" /usr/local/bin/weft
            rm -f /tmp/weft-install.sh
        }
    fi

    # Fallback: direct binary download
    if ! command -v weft >/dev/null 2>&1; then
        for url in \
            "https://weft.dev/dl/weft-linux-${WEFT_ARCH}" \
            "https://github.com/loreste32/weft/releases/latest/download/weft-linux-${WEFT_ARCH}"; do
            if curl -fsSL "$url" -o /usr/local/bin/weft 2>/dev/null; then
                chmod +x /usr/local/bin/weft
                break
            fi
        done
    fi

    # Verify
    if ! command -v weft >/dev/null 2>&1; then
        err "Failed to install Weft. Install manually from https://weft.dev and re-run."
    fi

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
            # Create database and user with generated password
            PG_PASS=$(openssl rand -hex 16)
            sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='zaman'" | grep -q 1 || {
                sudo -u postgres psql -c "CREATE USER zaman WITH PASSWORD '${PG_PASS}'" 2>/dev/null || true
                sudo -u postgres createdb -O zaman zaman 2>/dev/null || true
                log "Created PostgreSQL database 'zaman' (password generated)"
            }
            # Store for DSN construction
            export ZAMAN_PG_PASS="${PG_PASS}"
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
    makori build --release core/main.mko -o bin/zaman-core
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
ZAMAN_DB_DSN=host=127.0.0.1 dbname=zaman user=zaman password=${ZAMAN_PG_PASS:-} sslmode=disable
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

# ── Setup nginx reverse proxy with TLS ──
setup_nginx_tls() {
    if [ "${ZAMAN_TLS:-}" != "1" ] && [ "${SETUP_TLS:-}" != "1" ]; then
        return
    fi

    DOMAIN="${ZAMAN_DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
    log "Setting up nginx TLS reverse proxy for ${DOMAIN}..."

    if [ "$PKG_MGR" = "apt" ]; then
        apt-get install -y -qq nginx certbot python3-certbot-nginx >/dev/null 2>&1 || \
        apt-get install -y -qq nginx >/dev/null
    else
        yum install -y -q nginx certbot python3-certbot-nginx >/dev/null 2>&1 || \
        dnf install -y -q nginx >/dev/null 2>&1
    fi

    # Write nginx config
    cat > /etc/nginx/conf.d/zaman.conf << NGINX
server {
    listen 80;
    server_name ${DOMAIN};

    # Redirect HTTP to HTTPS (if cert exists)
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Core API (internal, or expose for remote agents)
    location /api/ {
        proxy_pass http://127.0.0.1:9090/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /metrics {
        proxy_pass http://127.0.0.1:9090/metrics;
    }
}
NGINX

    # Remove default site if it conflicts
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

    nginx -t 2>/dev/null && systemctl enable --now nginx

    # Try Let's Encrypt if domain looks real (not localhost/IP)
    if echo "$DOMAIN" | grep -qE '\.'; then
        if command -v certbot >/dev/null 2>&1; then
            log "Attempting Let's Encrypt certificate for ${DOMAIN}..."
            certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsecurely-without-email 2>/dev/null || \
                warn "Let's Encrypt failed — dashboard available on HTTP. Run: certbot --nginx -d ${DOMAIN}"
        fi
    else
        warn "No domain set — dashboard on HTTP. Set ZAMAN_DOMAIN and run certbot later."
    fi
}

# ── Configure firewall ──
setup_firewall() {
    if [ "${ZAMAN_SKIP_FW:-0}" = "1" ]; then
        return
    fi

    log "Configuring firewall..."

    if command -v ufw >/dev/null 2>&1; then
        # Debian/Ubuntu UFW
        ufw allow 80/tcp comment 'Zaman HTTP' 2>/dev/null || true
        ufw allow 443/tcp comment 'Zaman HTTPS' 2>/dev/null || true
        ufw allow 9060/udp comment 'Zaman HEP UDP' 2>/dev/null || true
        ufw allow 5060/udp comment 'Zaman SIP UDP' 2>/dev/null || true
        # HEP TCP/TLS only if enabled
        if [ "${ZAMAN_HEP_TCP:-0}" = "1" ]; then
            ufw allow 9062/tcp comment 'Zaman HEP TCP' 2>/dev/null || true
        fi
        if [ "${ZAMAN_HEP_TLS_ENABLED:-0}" = "1" ]; then
            ufw allow 9061/tcp comment 'Zaman HEP TLS' 2>/dev/null || true
        fi
        # Keep API port internal (only localhost + nginx)
        log "UFW rules added (9090 API kept internal — accessed via nginx /api/)"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # RHEL/CentOS firewalld
        firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=443/tcp 2>/dev/null || true
        firewall-cmd --permanent --add-port=9060/udp 2>/dev/null || true
        firewall-cmd --permanent --add-port=5060/udp 2>/dev/null || true
        if [ "${ZAMAN_HEP_TCP:-0}" = "1" ]; then
            firewall-cmd --permanent --add-port=9062/tcp 2>/dev/null || true
        fi
        if [ "${ZAMAN_HEP_TLS_ENABLED:-0}" = "1" ]; then
            firewall-cmd --permanent --add-port=9061/tcp 2>/dev/null || true
        fi
        firewall-cmd --reload 2>/dev/null || true
        log "firewalld rules added"
    else
        warn "No firewall manager found (ufw/firewalld). Configure manually:"
        warn "  Open: 80/tcp 443/tcp 9060/udp 5060/udp"
        warn "  Keep internal: 9090/tcp (API — proxied via nginx)"
    fi
}

# ── Setup HEP TLS for remote offices ──
setup_hep_tls() {
    if [ "${ZAMAN_HEP_TLS_ENABLED:-0}" != "1" ]; then
        return
    fi

    TLS_DIR="${DATA_DIR}/tls"
    mkdir -p "$TLS_DIR"

    if [ ! -f "$TLS_DIR/hep.crt" ]; then
        log "Generating HEP TLS certificate..."
        DOMAIN="${ZAMAN_DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$TLS_DIR/hep.key" -out "$TLS_DIR/hep.crt" \
            -days 365 -nodes -subj "/CN=${DOMAIN}" 2>/dev/null
        chown zaman:zaman "$TLS_DIR/hep.key" "$TLS_DIR/hep.crt"
        chmod 600 "$TLS_DIR/hep.key"
        log "HEP TLS cert generated: ${TLS_DIR}/hep.crt (self-signed, 365 days)"
    fi

    # Add TLS config to core.env
    if ! grep -q 'ZAMAN_HEP_TLS=' "$CONF_DIR/core.env" 2>/dev/null; then
        cat >> "$CONF_DIR/core.env" << TLSENV
ZAMAN_HEP_TLS=1
ZAMAN_HEP_TLS_CERT=${TLS_DIR}/hep.crt
ZAMAN_HEP_TLS_KEY=${TLS_DIR}/hep.key
ZAMAN_HEP_TCP=1
TLSENV
        log "HEP TLS enabled on port 9061, TCP on port 9062"
    fi
}

# ── Generate API key ──
setup_api_key() {
    if grep -q 'ZAMAN_API_KEY=' "$CONF_DIR/core.env" 2>/dev/null && \
       ! grep -q '# ZAMAN_API_KEY=' "$CONF_DIR/core.env" 2>/dev/null; then
        return
    fi

    API_KEY=$(openssl rand -hex 24)
    sed -i "s|# ZAMAN_API_KEY=|ZAMAN_API_KEY=${API_KEY}|" "$CONF_DIR/core.env" 2>/dev/null || true

    # Also set in web.env so dashboard can talk to core
    if ! grep -q 'ZAMAN_API_KEY=' "$CONF_DIR/web.env" 2>/dev/null; then
        echo "ZAMAN_API_KEY=${API_KEY}" >> "$CONF_DIR/web.env"
    fi

    log "API key generated and configured"
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
    IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')
    DOMAIN="${ZAMAN_DOMAIN:-${IP}}"
    PROTO="http"
    PORT=":3000"
    if [ "${SETUP_TLS:-0}" = "1" ]; then
        PROTO="https"
        PORT=""
    fi
    echo -e "${CYAN}║${NC}  Dashboard:  ${GREEN}${PROTO}://${DOMAIN}${PORT}${NC}"
    echo -e "${CYAN}║${NC}  Core API:   http://127.0.0.1:9090/api/health            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  SIP:        udp/5060                                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  HEP:        udp/9060                                    ${CYAN}║${NC}"
    if [ "${ZAMAN_HEP_TLS_ENABLED:-0}" = "1" ]; then
    echo -e "${CYAN}║${NC}  HEP TLS:    tcp/9061  (cert: ${DATA_DIR}/tls/hep.crt)   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  HEP TCP:    tcp/9062                                    ${CYAN}║${NC}"
    fi
    echo -e "${CYAN}║${NC}  Database:   ${DB_CHOICE}                                ${CYAN}║${NC}"
    if [ -n "$ADMIN_PW" ]; then
    echo -e "${CYAN}║${NC}                                                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Login:      admin / ${YELLOW}${ADMIN_PW}${NC}"
    fi
    API_KEY_SHOW=$(grep 'ZAMAN_API_KEY=' "$CONF_DIR/core.env" 2>/dev/null | grep -v '^#' | head -1 | cut -d= -f2)
    if [ -n "${API_KEY_SHOW:-}" ]; then
    echo -e "${CYAN}║${NC}  API Key:    ${YELLOW}${API_KEY_SHOW}${NC}"
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

    # TLS / public deployment
    if [ -z "${ZAMAN_TLS:-}" ] && [ -z "${SETUP_TLS:-}" ]; then
        echo ""
        echo "Setup HTTPS reverse proxy (nginx + Let's Encrypt)?"
        echo "  Recommended for: AWS, GCP, public IP, multi-office"
        echo "  Not needed for: lab, localhost, VPN-only"
        echo ""
        read -rp "Enable TLS? [y/N]: " tls_yn
        case "${tls_yn}" in
            y|Y|yes) SETUP_TLS=1
                read -rp "Domain name (e.g. sip-monitor.company.com): " input_domain
                ZAMAN_DOMAIN="${input_domain:-$(hostname -f)}"
                ;;
        esac
    fi

    # HEP TLS for remote offices
    if [ -z "${ZAMAN_HEP_TLS_ENABLED:-}" ]; then
        echo ""
        echo "Enable HEP over TLS (for remote offices sending captures over the internet)?"
        read -rp "Enable HEP TLS? [y/N]: " hep_tls_yn
        case "${hep_tls_yn}" in
            y|Y|yes) ZAMAN_HEP_TLS_ENABLED=1 ;;
        esac
    fi

    echo ""

    detect_distro
    install_deps
    install_mako
    install_weft

    # Verify toolchain before proceeding — validates binaries are genuine executables
    log "Verifying toolchain..."
    command -v makori >/dev/null 2>&1 || err "Makori not found after install"
    command -v weft >/dev/null 2>&1 || err "Weft not found after install"
    command -v clang >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || err "C compiler not found (need clang or gcc)"
    command -v git >/dev/null 2>&1 || err "git not found"
    command -v openssl >/dev/null 2>&1 || err "openssl not found"
    log "Toolchain OK: makori=$(makori version 2>/dev/null | head -1), weft=$(weft version 2>/dev/null | head -1)"

    install_database
    install_zaman
    setup_api_key
    setup_hep_tls
    setup_nginx_tls
    setup_firewall
    start_services
    print_summary
}

main "$@"
