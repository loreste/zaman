# Zaman Deployment Guide

Production deployment guide for Zaman v0.4. Keep environment-specific hosts,
keys, and server labels out of source control. Use environment files, nginx,
firewall rules, and runtime labels managed from the dashboard.

---

## Sizing

| Traffic | Calls/day | CPU | RAM | Disk | Notes |
|---------|-----------|-----|-----|------|-------|
| Small | 1,000–10,000 | 2 vCPU | 2 GB | 20 GB | Single site |
| Medium | 10,000–100,000 | 4 vCPU | 8 GB | 100 GB SSD | Production |
| Large | 100,000–1M | 8 vCPU | 16 GB | 500 GB SSD | Multi-site |

Rule of thumb: one captured SIP message is roughly 1 KB before index overhead.
At 300K messages/hour with 2-day retention, expect ~50 GB of PostgreSQL data.

---

## Network Ports

| Port | Protocol | Direction | Purpose | Exposure |
|------|----------|-----------|---------|----------|
| 443 | TCP | inbound | Dashboard HTTPS via nginx | Users or VPN |
| 80 | TCP | inbound | HTTP redirect to HTTPS | Users or VPN |
| 5060 | UDP | inbound | SIP capture | SIP infrastructure |
| 9060 | UDP | inbound | HEP3 capture | HEP agents |
| 9090 | TCP | internal | Core API | localhost only (UFW blocked) |
| 3000 | TCP | internal | Web dashboard | localhost only (UFW blocked) |

---

## Firewall

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP redirect
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 5060/udp  # SIP
sudo ufw allow 9060/udp  # HEP
sudo ufw enable
```

Ports 9090 and 3000 must NOT be exposed externally. Nginx proxies to 3000.

---

## PostgreSQL Tuning

For 8 GB RAM servers:

```bash
sudo -u postgres psql -c "
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET effective_cache_size = '6GB';
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET max_parallel_workers_per_gather = 2;
"
sudo systemctl restart postgresql
```

---

## Systemd Units

**Core** (`/etc/systemd/system/zaman-core.service`):
```ini
[Service]
ExecStart=/opt/zaman/bin/zaman-core
EnvironmentFile=-/etc/zaman/core.env
User=zaman
Restart=always
RestartSec=5
```

**Web** (`/etc/systemd/system/zaman-web.service`):
```ini
[Service]
ExecStart=/opt/zaman/bin/zaman-web
EnvironmentFile=-/etc/zaman/web.env
User=zaman
Restart=always
RestartSec=5
```

---

## Backups

Daily PostgreSQL backup with 7-day rotation:

```bash
# /etc/cron.d/zaman-backup
0 2 * * * zaman pg_dump -Fc zaman -f /opt/zaman/backups/zaman-$(date +\%Y\%m\%d).dump && find /opt/zaman/backups -name "*.dump" -mtime +7 -delete
```

---

## Cross-Compilation

Build for Linux from macOS:

```bash
cd core-go && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/zaman-core .
cd web && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/zaman-web .
```

Both binaries are statically linked with zero external dependencies.

---

## Deployment Steps

1. Build or cross-compile both binaries
2. SCP to server: `scp bin/zaman-core bin/zaman-web user@server:/opt/zaman/bin/`
3. Copy static files: `scp -r web/static/* user@server:/opt/zaman/web/static/`
4. Set permissions: `chown -R zaman:zaman /opt/zaman`
5. Configure `/etc/zaman/core.env` and `/etc/zaman/web.env`
6. Restart services: `systemctl restart zaman-core zaman-web`
7. Verify: `curl http://127.0.0.1:9090/api/health`
