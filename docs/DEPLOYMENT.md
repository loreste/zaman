# Zaman — Deployment Guide

## Sizing recommendations

| Traffic | Calls/day | Database | CPU | RAM | Disk | Notes |
|---------|-----------|----------|-----|-----|------|-------|
| **Lab / POC** | < 1,000 | SQLite | 1 vCPU | 1 GB | 10 GB | Laptop, dev VM |
| **Small office** | 1,000–10,000 | SQLite | 2 vCPU | 2 GB | 20 GB | Single site |
| **Medium** | 10,000–100,000 | PostgreSQL | 4 vCPU | 4 GB | 50 GB SSD | Regional deployment |
| **Large** | 100,000–1M | PostgreSQL | 8 vCPU | 8 GB | 200 GB SSD | Multi-office, ITSP |
| **Carrier** | 1M+ | ClickHouse | 8+ vCPU | 16+ GB | 500 GB+ SSD | Millions of calls, long retention |

**Rule of thumb:** each captured SIP message is ~1 KB in the database. 100,000 calls/day ≈ 500,000 messages ≈ 500 MB/day ≈ 15 GB/month.

## Cloud instances

| Provider | Small | Medium | Large |
|----------|-------|--------|-------|
| **AWS** | t3.small | t3.xlarge | m6i.2xlarge |
| **GCP** | e2-small | e2-standard-4 | n2-standard-8 |
| **Azure** | B2s | D4s_v3 | D8s_v3 |
| **Hetzner** | CPX11 | CPX31 | CPX51 |
| **DigitalOcean** | s-2vcpu-2gb | s-4vcpu-8gb | s-8vcpu-16gb |

## Network ports

| Port | Protocol | Direction | Purpose | Open to |
|------|----------|-----------|---------|---------|
| 443 | TCP | inbound | Dashboard (HTTPS via nginx) | Users / VPN |
| 80 | TCP | inbound | HTTP redirect → HTTPS | Users |
| 9060 | UDP | inbound | HEP v3 (from SIP proxies) | SIP infrastructure |
| 5060 | UDP | inbound | SIP capture + echo | SIP infrastructure |
| 9061 | TCP | inbound | HEP over TLS (remote offices) | Remote agents |
| 9062 | TCP | inbound | HEP over TCP | LAN agents |
| 9090 | TCP | **localhost only** | Core API (proxied via nginx) | Do not expose |
| 3000 | TCP | **localhost only** | Dashboard (behind nginx) | Do not expose |

**AWS Security Group example:**

```
Inbound:
  443/tcp    → 0.0.0.0/0           (dashboard)
  9060/udp   → 10.0.0.0/8          (HEP from internal)
  9061/tcp   → 0.0.0.0/0           (HEP TLS from remote offices)
  5060/udp   → 10.0.0.0/8          (SIP)
  22/tcp     → your-ip/32          (SSH)
```

## Architecture patterns

### Single site

```
┌─────────────┐    HEP/UDP     ┌──────────┐
│ Kamailio    │───────────────→│          │
│ FreeSWITCH  │    :9060       │  Zaman   │──→ Browser
│ Asterisk    │                │  :443    │
└─────────────┘                └──────────┘
                                  SQLite
```

One Zaman instance, SIP proxies on the same LAN send HEP over UDP. Dashboard behind nginx with TLS.

### Multi-office

```
Office A                        Data center
┌──────────┐   HEP/TLS :9061  ┌──────────┐
│ Kamailio │──────────────────→│          │
└──────────┘     internet      │  Zaman   │──→ Browser
                               │  :443    │
Office B                       │          │
┌──────────┐   HEP/TLS :9061  │          │
│ OpenSIPS │──────────────────→│          │
└──────────┘     internet      └──────────┘
                                PostgreSQL
```

Remote offices send HEP over TLS. Dashboard accessible over HTTPS with RBAC.

### Carrier / ITSP

```
┌───────────┐
│ SBC farm  │──┐
└───────────┘  │  HEP/UDP
┌───────────┐  │  (private net)   ┌──────────┐
│ Kamailio  │──┼─────────────────→│  Zaman   │──→ NOC dashboard
│ cluster   │  │                  │  :443    │──→ Prometheus
└───────────┘  │                  │          │──→ Grafana
┌───────────┐  │                  └──────────┘
│ FreeSWITCH│──┘                   ClickHouse
│ media     │                      (separate)
└───────────┘
```

ClickHouse on a dedicated server or cluster. Zaman core writes via HTTP. Multiple HEP sources on a private network. Dashboard behind nginx, Prometheus scrapes `/metrics`.

## Install commands by scenario

### Lab (quickest)

```bash
sudo bash install.sh
# Pick 1 (SQLite), skip TLS, skip HEP TLS
# Done in 2 minutes
```

### Production single-site

```bash
sudo ZAMAN_DB=postgres bash install.sh
# Pick TLS: yes, enter domain
# Pick HEP TLS: no (LAN only)
```

### Multi-office with remote agents

```bash
sudo ZAMAN_DB=postgres bash install.sh
# Pick TLS: yes, enter domain
# Pick HEP TLS: yes
# After install, distribute /opt/zaman/data/tls/hep.crt to remote offices
```

### Carrier scale

```bash
# Install ClickHouse separately (or use managed ClickHouse Cloud)
sudo ZAMAN_DB=clickhouse ZAMAN_CH_URL=http://clickhouse-host:8123 bash install.sh
# Pick TLS: yes
# Pick HEP TLS: yes
```

### Non-interactive (CI / automation)

```bash
sudo ZAMAN_DB=postgres \
     ZAMAN_TLS=1 \
     ZAMAN_DOMAIN=sip.company.com \
     ZAMAN_HEP_TLS_ENABLED=1 \
     bash install.sh
```

## Post-install checklist

- [ ] Log in to the dashboard and change the admin password
- [ ] Create operator accounts for NOC staff
- [ ] Configure alert channels (Slack/webhook/email) at `/alerts`
- [ ] Set SLA targets at `/sla`
- [ ] Point SIP proxies to send HEP to Zaman's port 9060 (or 9061 for TLS)
- [ ] Verify captures appear in the dashboard
- [ ] Set up Prometheus scrape if using external monitoring
- [ ] Review `/etc/zaman/core.env` and adjust retention, probe, echo settings
- [ ] If public-facing: restrict `ZAMAN_DASHBOARD_ALLOW_IPS` to office/VPN ranges
- [ ] Generate API tokens for any automation scripts

## Retention planning

| Retention | 10k calls/day | 100k calls/day | 1M calls/day |
|-----------|---------------|----------------|--------------|
| 7 days | 350 MB | 3.5 GB | 35 GB |
| 30 days | 1.5 GB | 15 GB | 150 GB |
| 90 days | 4.5 GB | 45 GB | 450 GB |
| 365 days | 18 GB | 180 GB | 1.8 TB |

Set `ZAMAN_DB_RETENTION_DAYS` in `/etc/zaman/core.env`. Default is 14 days. Set to `0` for no auto-deletion.

ClickHouse handles large retention better than SQLite or PostgreSQL — use monthly partitions and ClickHouse's built-in TTL if needed.

## Upgrades

```bash
cd /opt/zaman
git pull
make build
sudo systemctl restart zaman-core zaman-web
```

Config in `/etc/zaman/` is preserved across upgrades. Database schema is auto-migrated.

## Backup

```bash
# SQLite
cp /opt/zaman/data/zaman.db /backup/zaman-$(date +%Y%m%d).db

# PostgreSQL
pg_dump -U zaman zaman > /backup/zaman-$(date +%Y%m%d).sql

# Config + users + alerts
tar czf /backup/zaman-config-$(date +%Y%m%d).tar.gz /etc/zaman/ /opt/zaman/data/*.json
```

## Troubleshooting

```bash
# Check service status
systemctl status zaman-core
systemctl status zaman-web

# View logs
journalctl -u zaman-core -f
journalctl -u zaman-web -f

# Health check
curl http://127.0.0.1:9090/api/health

# Test HEP connectivity
python3 /opt/zaman/scripts/send_hep.py --port 9060

# Test SIP echo
python3 /opt/zaman/scripts/send_options.py 127.0.0.1 5060
```
