# Zaman Deployment Guide

This guide covers production-track Zaman v0.3 deployments. Keep environment-
specific hosts, keys, customer names, and server labels out of source control.
Use environment files, nginx configuration, firewall rules, and runtime labels
managed from the dashboard.

---

## Sizing

| Traffic | Calls/day | Recommended DB | CPU | RAM | Disk | Notes |
|---------|-----------|----------------|-----|-----|------|-------|
| Lab / POC | < 1,000 | SQLite | 1 vCPU | 1 GB | 10 GB | Local demo or test VM |
| Small | 1,000-10,000 | SQLite or PostgreSQL | 2 vCPU | 2 GB | 20 GB | Single site |
| Medium | 10,000-100,000 | PostgreSQL | 4 vCPU | 4 GB | 50 GB SSD | Production single region |
| Large | 100,000-1M | PostgreSQL | 8 vCPU | 8 GB | 200 GB SSD | Multi-site ITSP |
| Carrier | 1M+ | ClickHouse | 8+ vCPU | 16+ GB | 500 GB+ SSD | Long retention/high volume |

Rule of thumb: one captured SIP message is roughly 1 KB before database/index
overhead. Plan retention from message volume, not just call volume.

---

## Network Ports

| Port | Protocol | Direction | Purpose | Exposure |
|------|----------|-----------|---------|----------|
| 443 | TCP | inbound | Dashboard HTTPS via nginx | Users or VPN |
| 80 | TCP | inbound | HTTP redirect to HTTPS | Users or VPN |
| 9060 | UDP | inbound | HEP3 from SIP infrastructure | SIP/HEP peers only |
| 9061 | TCP | inbound | HEP3 over TLS | Remote HEP peers only |
| 9062 | TCP | inbound | HEP3 over TCP | LAN HEP peers only |
| 5060 | UDP | inbound | SIP capture/echo | SIP infrastructure only |
| 9090 | TCP | local | Core API | localhost/nginx only |
| 3000 | TCP | local | Web UI | localhost/nginx only |

Avoid exposing 9090 or 3000 directly. Put nginx in front of the web UI and keep
the core API private.

---

## Install Modes

### Lab

```bash
sudo ZAMAN_DB=sqlite bash install.sh
```

Use this for local testing and quick demos.

### Production With PostgreSQL

```bash
sudo ZAMAN_DB=postgres ZAMAN_TLS=1 ZAMAN_DOMAIN=your-dashboard-domain bash install.sh
```

Use a real DNS name in `ZAMAN_DOMAIN` at install time. Do not commit that value
to the repository.

### High Volume With ClickHouse

```bash
sudo ZAMAN_DB=clickhouse ZAMAN_CH_URL=your-clickhouse-http-url bash install.sh
```

Use ClickHouse when retention and ingest rate outgrow PostgreSQL.

### Non-Interactive Automation

```bash
sudo ZAMAN_DB=postgres \
  ZAMAN_TLS=1 \
  ZAMAN_DOMAIN=your-dashboard-domain \
  ZAMAN_HEP_TLS_ENABLED=1 \
  bash install.sh
```

---

## Recommended Production Shape

```text
SIP proxy / SBC / PBX
        |
        | HEP3 UDP/TCP/TLS
        v
zaman-core  ---> PostgreSQL or ClickHouse
        |
        | localhost API
        v
zaman-web
        |
        | localhost
        v
nginx :80/:443
        |
        v
operators / NOC / VPN
```

For live voice networks, change SIP proxy configuration conservatively:

1. Back up the current SIP proxy config.
2. Add HEP mirroring without changing routing logic.
3. Validate syntax with the SIP proxy's native config checker.
4. Reload only if the checker passes.
5. Confirm HEP traffic appears in `/messages`, `/calls`, and `/ladder`.

---

## Post-Install Checklist

- [ ] Log in and rotate the initial admin password.
- [ ] Create named admin/operator/viewer accounts.
- [ ] Configure nginx and TLS for dashboard access.
- [ ] Keep `zaman-core` and `zaman-web` bound behind nginx.
- [ ] Set `ZAMAN_API_KEY` for the core API.
- [ ] Configure `ZAMAN_HEP_ALLOW` or firewall rules for trusted HEP peers.
- [ ] Point SIP infrastructure at HEP port 9060, 9061, or 9062.
- [ ] Verify realtime CPS, concurrent calls, live feed, and active calls.
- [ ] Open a real `/ladder?call_id=...` page and confirm all SIP responses show.
- [ ] Label SIP nodes in `/noc` and site/customer/carrier IPs in `/ip`.
- [ ] Set SLA targets in `/sla`.
- [ ] Configure alert rules and delivery channels in `/alerts`.
- [ ] Configure retention in `/etc/zaman/core.env`.
- [ ] Generate API tokens for automation from `/admin/tokens`.
- [ ] Set up Prometheus scraping if external monitoring is required.

---

## HEP Sender Notes

Zaman expects HEP3 packets from SIP infrastructure. The exact sender syntax
depends on the SIP proxy or capture agent, but the operational pattern is the
same:

- Send mirrored SIP signaling to the Zaman HEP listener.
- Prefer a private network or HEP/TLS for remote sites.
- Use runtime HEP agent names to identify sources.
- Do not hardcode production collector IPs in committed examples.
- Confirm received traffic in `/messages` and grouped dialogs in `/calls`.

---

## Runtime Labels

Runtime labels are stored outside source control:

| Label Type | UI | Runtime File |
|------------|----|--------------|
| Node/server names | `/noc` | `zaman-node-names.json` |
| Site/customer/carrier IP labels | `/ip` | `zaman-site-labels.json` |

Use these labels for local names such as SIP proxy names, carriers, customer
sites, and private routing identifiers. Do not commit those values.

---

## Retention Planning

| Retention | 10k calls/day | 100k calls/day | 1M calls/day |
|-----------|---------------|----------------|--------------|
| 7 days | 350 MB | 3.5 GB | 35 GB |
| 30 days | 1.5 GB | 15 GB | 150 GB |
| 90 days | 4.5 GB | 45 GB | 450 GB |
| 365 days | 18 GB | 180 GB | 1.8 TB |

Set `ZAMAN_DB_RETENTION_DAYS` in `/etc/zaman/core.env`. It prunes raw captures,
call summaries, and daily rollups. Use `0` only when an external retention
process is in place.

---

## Upgrades

```bash
cd /opt/zaman
git pull
make build
sudo systemctl restart zaman-core zaman-web
```

Configuration in `/etc/zaman/` is preserved. Database schema migrations run at
startup.

---

## Backup

```bash
# SQLite
cp /opt/zaman/data/zaman.db /backup/zaman-$(date +%Y%m%d).db

# PostgreSQL
pg_dump -U zaman zaman > /backup/zaman-$(date +%Y%m%d).sql

# Config and runtime JSON state
tar czf /backup/zaman-config-$(date +%Y%m%d).tar.gz /etc/zaman/ /opt/zaman/data/*.json
```

Back up runtime JSON files because they contain users, tokens, alert rules,
node labels, IP labels, and audit state.

---

## Troubleshooting

```bash
systemctl status zaman-core
systemctl status zaman-web

journalctl -u zaman-core -f
journalctl -u zaman-web -f

curl http://127.0.0.1:9090/api/health

python3 /opt/zaman/scripts/send_hep.py --port 9060
python3 /opt/zaman/scripts/send_options.py 127.0.0.1 5060
```

Useful UI checks:

- `/` for realtime CPS, concurrent calls, active calls, and live feed.
- `/messages` for raw capture visibility and filters.
- `/calls` for active and recent dialogs.
- `/ladder?call_id=...` for full SIP ladder rows and responses.
- `/ip` for source/destination history and labels.
- `/report` for exportable telecom KPIs.
