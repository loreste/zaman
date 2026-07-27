#!/bin/bash
# Install Zaman as systemd services
# Run as root: sudo bash deploy/install.sh
set -euo pipefail

INSTALL_DIR="/opt/zaman"
CONF_DIR="/etc/zaman"

echo "Installing Zaman to ${INSTALL_DIR}"

# Create user
id -u zaman >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" zaman

# Create directories
mkdir -p "$INSTALL_DIR"/{bin,data,web,scripts}
mkdir -p "$CONF_DIR"

# Copy files
cp bin/zaman-core "$INSTALL_DIR/bin/"
cp -r web/* "$INSTALL_DIR/web/"
cp -r scripts/* "$INSTALL_DIR/scripts/"

# Set ownership
chown -R zaman:zaman "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR/data"

# Install systemd units
cp deploy/zaman-core.service /etc/systemd/system/
cp deploy/zaman-web.service /etc/systemd/system/

# Create default env files if not present
[ -f "$CONF_DIR/core.env" ] || cat > "$CONF_DIR/core.env" << 'EOF'
# Zaman core configuration
# ZAMAN_DB_DRIVER=sqlite
# ZAMAN_DB=/opt/zaman/data/zaman.db
# ZAMAN_PROBE=0
# ZAMAN_API_KEY=
# ZAMAN_HEP_TCP=0
# ZAMAN_HEP_TLS=0
EOF

[ -f "$CONF_DIR/web.env" ] || cat > "$CONF_DIR/web.env" << 'EOF'
# Zaman dashboard configuration
# ZAMAN_CORE=http://127.0.0.1:9090
# ZAMAN_AUTH=1
# ZAMAN_DASHBOARD_ALLOW_IPS=
EOF

systemctl daemon-reload
echo ""
echo "Installed. Start with:"
echo "  systemctl enable --now zaman-core"
echo "  systemctl enable --now zaman-web"
echo ""
echo "Config: $CONF_DIR/core.env and $CONF_DIR/web.env"
echo "Data:   $INSTALL_DIR/data/"
echo "Logs:   journalctl -u zaman-core / journalctl -u zaman-web"
