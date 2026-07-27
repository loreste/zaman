# Zaman

SIP monitoring for people who are tired of running five systems to answer one question.

![Call Ladder](docs/call-ladder.png)
![Reports](docs/reports.png)

## Why this exists

If you run a VoIP network, you probably have one tool for SIP capture, another for metrics, another for dashboards, some scripts for keepalive checks, and maybe a wiki page explaining how they all connect. Each tool is fine on its own. The problem is gluing them together, keeping them running, and training new engineers on four different UIs.

Zaman started as a question: what if one process did all of that? Not better than each tool individually — just simpler to deploy and operate as a whole.

It captures SIP and HEP traffic, stores it, shows a live dashboard with call ladders, and exposes Prometheus-compatible metrics. One binary for the core, one process for the dashboard. No external databases required unless you want them.

## Install

### One-line install (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo bash
```

The installer:
- Detects your distro (Debian/Ubuntu, RHEL/CentOS/Fedora/Rocky)
- Installs all dependencies (Mako, Weft, clang, openssl)
- Asks you to pick a database (SQLite, PostgreSQL, or ClickHouse)
- Installs and configures the chosen database
- Builds the core binary
- Creates systemd services
- Starts everything
- Prints the dashboard URL and admin password

To pick the database non-interactively:

```bash
# SQLite (default, zero-config)
curl -fsSL .../install.sh | sudo ZAMAN_DB=sqlite bash

# PostgreSQL
curl -fsSL .../install.sh | sudo ZAMAN_DB=postgres bash

# ClickHouse (millions of calls/day)
curl -fsSL .../install.sh | sudo ZAMAN_DB=clickhouse bash
```

### Docker

```bash
# SQLite (simplest)
docker compose up

# With PostgreSQL
docker compose --profile pg up

# With ClickHouse
docker compose --profile ch up
```

### Manual build

Requirements: [Mako](https://mako-lang.dev) ≥ 0.4.17, [Weft](https://weft.dev).

```bash
make build          # → bin/zaman-core
make smoke          # end-to-end test
./scripts/demo.sh   # core + dashboard → http://127.0.0.1:3000
```

### Systemd (after manual build)

```bash
sudo bash deploy/install.sh
sudo systemctl enable --now zaman-core zaman-web
```

Config: `/etc/zaman/core.env` and `/etc/zaman/web.env`. Logs: `journalctl -u zaman-core`.

## What it does

```
 SIP/HEP agents          Browser
       │                    │
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│  zaman-core  │◄───►│  zaman-web   │
│  (Mako)      │ API │  (Weft/HTMX) │
│  :5060 SIP   │     │  :3000       │
│  :9060 HEP   │     └──────────────┘
│  :9090 HTTP  │
└──────────────┘
```

**Capture** — SIP over UDP, HEPv3 over UDP/TCP/TLS. Compatible with any HEP-speaking SIP proxy or agent.

**Dashboard** — Real-time overview with active calls, ASR/NER gauges, node health, anomaly detection. HTMX live-refresh, no JavaScript frameworks.

**Call ladder** — SIP flow diagrams with directional arrows between endpoints. PCAP export for Wireshark. Call recording upload and playback. Public share links.

**Search** — Filter by Call-ID, agent/server, SIP method, transport, endpoint IP. Save searches. Export as JSON, CSV, or PCAP.

**Reports** — Telecom KPIs (ASR, NER), response code breakdown, top talkers, agent inventory, daily rollups.

**SLA** — Per-agent and per-destination SLA tracking with configurable thresholds.

**NOC** — Dedicated network operations view with node status table, anomaly alerts, traffic summary.

**Alerting** — Threshold rules on ASR, error rates, 5xx spikes, auth failures. Notify via Slack, generic webhook, or email. Retry on failure.

**Auth** — RBAC (admin/operator/viewer), API tokens, audit log, password policy, IP allowlisting, LDAP/SSO.

**Metrics** — Prometheus-compatible `/metrics`, Grafana datasource API.

**CLI** — `scripts/zaman-cli.sh` for terminal search, export, and ASCII call ladders.

## Database

Three backends, depending on scale:

| Backend | Best for | Config |
|---------|----------|--------|
| **SQLite** | Single instance, lab, small deployments | default — zero config |
| **PostgreSQL** | Production with existing Postgres infrastructure | `ZAMAN_DB_DRIVER=postgres` |
| **ClickHouse** | High volume — millions of calls/day, long retention | `ZAMAN_DB_DRIVER=clickhouse` |

Tables are auto-created on first run for all backends.

## HEP

Native HEPv3 collector. Point your existing SIP proxies at Zaman's HEP port and it works.

| Transport | Default | Enable |
|-----------|---------|--------|
| UDP | `:9060` | always on |
| TCP | `:9062` | `ZAMAN_HEP_TCP=1` |
| TLS | `:9061` | `ZAMAN_HEP_TLS=1` + cert/key |

Optional HEP password and peer IP allowlisting are supported.

## Dashboard pages

| Page | What it shows |
|------|--------------|
| **Overview** | Active calls, ASR, error rate, node summary, traffic charts with time windows (5m–24h + custom), live capture feed |
| **NOC** | Full network operations — node status table, anomaly alerts, agent inventory |
| **Messages** | Multi-field search, saved filters, JSON/CSV/PCAP export |
| **Calls** | SIP ladder with arrows, PCAP download, recording player, public share links, B2BUA correlation |
| **Probe** | Active OPTIONS RTT test |
| **Metrics** | Core health, capture counters, HEP ingest, real-time window, telecom KPIs, method/response charts, Prometheus + Grafana config |
| **Reports** | ASR/NER gauges, response codes, top talkers, agents, daily rollups |
| **SLA** | Per-agent and per-destination SLA with configurable targets |
| **Alerts** | Threshold rules, notification channels (Slack/webhook/email), alert history |
| **Users** | User management with inline password reset |
| **API Tokens** | Generate/revoke Bearer tokens for automation |
| **Audit Log** | Login attempts, config changes, exports |

## Auth

Three roles: **admin** (full access), **operator** (+ probe, alerts, SLA), **viewer** (read-only).

Disable with `ZAMAN_AUTH=0` for lab use.

API tokens for scripts: `Authorization: Bearer <token>`.

IP allowlisting: `ZAMAN_DASHBOARD_ALLOW_IPS=10.0.0.,192.168.1.`

LDAP: set `ZAMAN_LDAP_URL` to your LDAP HTTP bind proxy.

## Integrations

**Prometheus** — scrape `/metrics` on the core port.

**Grafana** — SimpleJSON datasource at `/api/grafana/`.

**LDAP/SSO** — `ZAMAN_LDAP_URL` env var.

**CLI** — `scripts/zaman-cli.sh health|kpi|nodes|search|calls|ladder|export`

## Configuration

| Env | Default | Purpose |
|-----|---------|---------|
| `ZAMAN_DB_DRIVER` | `sqlite` | `sqlite`, `postgres`, or `clickhouse` |
| `ZAMAN_DB` | `data/zaman.db` | SQLite path |
| `ZAMAN_DB_DSN` | _(localhost)_ | PostgreSQL connection string |
| `ZAMAN_CH_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `ZAMAN_CH_DB` | `zaman` | ClickHouse database name |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete older captures (0 = keep all) |
| `ZAMAN_SIP_HOST` | `0.0.0.0` | Bind address |
| `ZAMAN_SIP_PORT` | `5060` | SIP UDP (or argv1) |
| `ZAMAN_HEP_PORT` | `9060` | HEP UDP (or argv2) |
| `ZAMAN_API_PORT` | `9090` | HTTP API (or argv3) |
| `ZAMAN_API_KEY` | _(empty)_ | Require key on API (except /health) |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | Which methods get auto-reply |
| `ZAMAN_PROBE` | `0` | Enable probe API |
| `ZAMAN_HEP_TCP` | `0` | Enable HEP/TCP |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP/TLS |
| `ZAMAN_HEP_TLS_CERT/KEY` | | PEM paths |
| `ZAMAN_HEP_PASSWORD` | _(empty)_ | HEP auth |
| `ZAMAN_HEP_ALLOW` | _(empty)_ | HEP peer allowlist |
| `ZAMAN_AUTH` | _(enabled)_ | Set `0` to disable dashboard auth |
| `ZAMAN_DASHBOARD_ALLOW_IPS` | _(empty)_ | IP allowlist for dashboard |
| `ZAMAN_RATE_LIMIT` | `100` | API requests/sec per IP (0 = disabled) |
| `ZAMAN_LDAP_URL` | _(empty)_ | LDAP HTTP bind proxy URL |
| `ZAMAN_BRAND_NAME` | `Zaman` | Custom dashboard title |
| `ZAMAN_BRAND_SUBTITLE` | `SIP monitoring · echo` | Custom subtitle |
| `ZAMAN_CORE` | `http://127.0.0.1:9090` | Core URL (for dashboard) |

## Scale

- **Small**: SQLite, single binary, laptop or VM. Thousands of calls/day. No dependencies.
- **Large**: ClickHouse backend, millions of calls/day, months of retention. Same binary, different env var.

The dashboard is stateless (HMAC-signed cookies). Run multiple instances behind a load balancer.

## Project layout

```
zaman/
  core/main.mko          # capture, echo, HEP, API, metrics (Mako)
  web/main.weft           # dashboard, auth, alerting (Weft + HTMX)
  install.sh              # universal Linux installer
  Dockerfile              # multi-stage build
  docker-compose.yml      # SQLite / PostgreSQL / ClickHouse profiles
  deploy/
    zaman-core.service    # systemd unit
    zaman-web.service     # systemd unit
    install.sh            # bare-metal installer (post-build)
  scripts/
    smoke.sh              # end-to-end test
    demo.sh               # local demo
    zaman-cli.sh          # command-line interface
    send_hep.py           # HEP test client
    send_options.py       # SIP OPTIONS test client
    gen_pcap.py           # PCAP generation
  spec.md                 # engineering spec
  SECURITY_REVIEW.md      # threat model
  docs/                   # screenshots
```

## Limitations

- No RTP/media capture or MOS scoring (SIP signaling only)
- No multi-node federation (single core instance)
- No built-in TLS on the dashboard (use a reverse proxy)
- Alert evaluation is poll-based (30s), not streaming
- The UI is server-rendered with HTMX — no client-side SPA

## License

Apache-2.0
