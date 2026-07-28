# Zaman

Enterprise SIP monitoring — capture, call ladders, metrics, alerting, and dashboards in one platform.

## Why this exists

A friend pointed out something obvious: there are plenty of tools to monitor VoIP networks, but they're all separate. You need one for SIP capture, another for metrics, another for dashboards, another for alerting, and then you spend a weekend wiring them together. Installation is never easy. Training new engineers means teaching four different UIs. And when something breaks at 3am, you're jumping between tabs trying to correlate what happened.

Zaman was built to fix that. Named after that friend, it puts SIP capture, call flow visualization, telecom KPIs, real-time alerting, and a live dashboard into a single platform that installs in one command.

It runs on SQLite out of the box — no external databases, no infrastructure prerequisites. When you outgrow that, switch to PostgreSQL or ClickHouse with one environment variable. Same binary, same dashboard, same API.

---

## Install

### One command (Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo bash
```

This single command handles everything:

1. **Detects your distro** — Debian, Ubuntu, RHEL, CentOS, Fedora, Rocky, AlmaLinux
2. **Installs all system dependencies** — clang, gcc, libc-dev, libssl-dev, pkg-config, python3, openssl, git
3. **Installs Mako** — the language the core is written in (tries official installer, falls back to direct download)
4. **Installs Weft** — the framework the dashboard runs on (same pattern)
5. **Verifies the toolchain** — confirms mako, weft, clang/gcc, git, openssl all work before proceeding
6. **Asks you to pick a database** — SQLite, PostgreSQL, or ClickHouse
7. **Installs and configures the database** — creates users, databases, passwords (all generated per install)
8. **Optionally sets up HTTPS** — nginx reverse proxy with Let's Encrypt
9. **Optionally enables HEP TLS** — generates certs for remote agents
10. **Configures firewall** — ufw (Debian) or firewalld (RHEL)
11. **Builds the core binary** from source
12. **Creates systemd services** with security hardening
13. **Generates unique credentials** — admin password, API key, database password
14. **Starts everything** and prints the dashboard URL

Non-interactive install:

```bash
# SQLite (default)
curl -fsSL .../install.sh | sudo ZAMAN_DB=sqlite bash

# PostgreSQL with HTTPS
curl -fsSL .../install.sh | sudo ZAMAN_DB=postgres ZAMAN_TLS=1 ZAMAN_DOMAIN=sip.company.com bash

# ClickHouse for carrier scale
curl -fsSL .../install.sh | sudo ZAMAN_DB=clickhouse bash
```

### Docker

```bash
docker compose up                     # SQLite
docker compose --profile pg up        # PostgreSQL
docker compose --profile ch up        # ClickHouse
```

### Manual build

Requires [Mako](https://mako-lang.dev) ≥ 0.4.18 and [Weft](https://weft.dev) on PATH.

```bash
make build          # → bin/zaman-core
make smoke          # end-to-end test (SIP echo, HEP UDP/TCP/TLS, probe, metrics)
./scripts/demo.sh   # core + dashboard → http://127.0.0.1:3000
```

For sizing recommendations, cloud instance types, architecture diagrams, and post-install checklists, see the **[Deployment Guide](docs/DEPLOYMENT.md)**.

---

## Features

### Capture

- SIP over UDP with OPTIONS echo
- HEPv3 over UDP, TCP, and TLS
- Compatible with Kamailio, OpenSIPS, FreeSWITCH, Asterisk, heplify, captagent
- Auth header redaction before storage
- REGISTER always returns 401 (never fakes a registrar)

### Dashboard

| Page | Purpose |
|------|---------|
| **Overview** | Hero KPIs (active calls, ASR, error rate), node health bar, traffic charts with selectable time windows (5m–24h + custom), live capture feed |
| **NOC** | Full network operations — node status table with health dots, anomaly alerts, traffic summary |
| **Messages** | Multi-field search (Call-ID, agent, method, transport, IP), saved searches, JSON/CSV/PCAP export |
| **Calls** | SIP ladder with directional arrows, PCAP download, call recording upload + playback, public share links, B2BUA leg correlation |
| **Probe** | Active OPTIONS RTT test against any host |
| **Metrics** | Core health, capture counters, HEP ingest stats, real-time 5m window, telecom KPIs, method + response code charts, Prometheus + Grafana config |
| **Reports** | ASR/NER gauges with thresholds, response code breakdown with percentage bars, top talkers, HEP agent inventory, daily rollups |
| **SLA** | Per-agent and per-destination SLA tracking with configurable ASR/NER/error targets |
| **Alerts** | Threshold rules, Slack/webhook/email channels with retry, alert history |
| **Users** | User management with inline password reset, role legend |
| **API Tokens** | Generate/revoke Bearer tokens for automation with usage hints |
| **Audit Log** | All auth and admin actions with human-readable timestamps |

### QoS and MOS

RTCP packets received via HEP (proto_type=5) are parsed for:
- Jitter (ms), packet loss (%), cumulative loss
- R-factor (ITU-T G.107 E-model)
- MOS (Mean Opinion Score, 1.0–5.0)

QoS data is attached to capture records and available via `GET /api/qos?call_id=X`.

### Multi-node federation

Remote Zaman instances forward captures to a central aggregator:

```bash
# Central instance accepts pushes
POST /api/federation/push   # JSON array or single record
GET  /api/federation/health  # connectivity check
```

### Alerting

- **Anomaly detection**: auth failure spikes, registration storms, SIP scanning, 5xx errors, busy (486) spikes
- **Threshold rules**: configurable on ASR, error rate, 5xx/4xx count, 401/403/503, INVITE rate, active calls
- **Channels**: Slack webhook, generic webhook (PagerDuty/Teams/Opsgenie), email (SMTP)
- **Retry**: 3 attempts with 1-second backoff

### Auth and security

- RBAC: **admin**, **operator**, **viewer**
- Signed session tokens (HMAC-SHA256, stateless)
- API tokens for automation (`Authorization: Bearer <token>`)
- Password policy (min 8 chars + digit)
- IP allowlisting (`ZAMAN_DASHBOARD_ALLOW_IPS`)
- LDAP/SSO support (`ZAMAN_LDAP_URL`)
- Audit log (all auth and admin actions)
- Rate limiting (100 req/s per IP, configurable)
- Dashboard TLS via nginx reverse proxy (configured by installer)

---

## Database

| Backend | Best for | Config |
|---------|----------|--------|
| **SQLite** | Single instance, lab, small deployments | default — zero config |
| **PostgreSQL** | Production, existing Postgres infrastructure | `ZAMAN_DB_DRIVER=postgres` |
| **ClickHouse** | Millions of calls/day, long retention | `ZAMAN_DB_DRIVER=clickhouse` |

Tables and indexes are auto-created on first run. Schema is identical across backends.

ClickHouse uses MergeTree with monthly partitions, SummingMergeTree for daily rollups, and communicates via the HTTP interface (no native driver needed).

---

## Integrations

| System | How |
|--------|-----|
| **Prometheus** | Scrape `/metrics` on the core port |
| **Grafana** | SimpleJSON datasource at `/api/grafana/` |
| **LDAP/SSO** | `ZAMAN_LDAP_URL` — HTTP bind proxy |
| **Kamailio/OpenSIPS** | HEP agent → Zaman port 9060 (UDP) or 9061 (TLS) |
| **heplify** | `heplify -hs zaman-host:9060` |
| **CLI** | `scripts/zaman-cli.sh health\|kpi\|nodes\|search\|calls\|ladder\|export` |

---

## Configuration

| Env | Default | Purpose |
|-----|---------|---------|
| **Database** | | |
| `ZAMAN_DB_DRIVER` | `sqlite` | `sqlite`, `postgres`, or `clickhouse` |
| `ZAMAN_DB` | `data/zaman.db` | SQLite path |
| `ZAMAN_DB_DSN` | _(localhost)_ | PostgreSQL connection string |
| `ZAMAN_CH_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `ZAMAN_CH_DB` | `zaman` | ClickHouse database name |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete older captures (0 = keep all) |
| **Network** | | |
| `ZAMAN_SIP_HOST` | `0.0.0.0` | Bind address for SIP/HEP |
| `ZAMAN_SIP_PORT` | `5060` | SIP UDP (or argv1) |
| `ZAMAN_HEP_PORT` | `9060` | HEP UDP (or argv2) |
| `ZAMAN_API_PORT` | `9090` | HTTP API (or argv3) |
| `ZAMAN_HEP_TCP` | `0` | Enable HEP over TCP |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP over TLS |
| `ZAMAN_HEP_TLS_CERT/KEY` | | PEM paths |
| **Security** | | |
| `ZAMAN_API_KEY` | _(empty)_ | Require key on API (except /health) |
| `ZAMAN_HEP_PASSWORD` | _(empty)_ | HEP password auth |
| `ZAMAN_HEP_ALLOW` | _(empty)_ | HEP peer IP allowlist |
| `ZAMAN_AUTH` | _(enabled)_ | Set `0` to disable dashboard auth |
| `ZAMAN_DASHBOARD_ALLOW_IPS` | _(empty)_ | IP allowlist for dashboard |
| `ZAMAN_RATE_LIMIT` | `100` | API requests/sec per IP |
| `ZAMAN_LDAP_URL` | _(empty)_ | LDAP HTTP bind proxy URL |
| **Behavior** | | |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | Which SIP methods get auto-reply |
| `ZAMAN_PROBE` | `0` | Enable active probe API |
| `ZAMAN_FEDERATION_TARGET` | _(empty)_ | URL to forward captures to central instance |
| `ZAMAN_BRAND_NAME` | `Zaman` | Custom dashboard title |
| `ZAMAN_BRAND_SUBTITLE` | `SIP monitoring · echo` | Custom subtitle |
| `ZAMAN_CORE` | `http://127.0.0.1:9090` | Core URL (for dashboard) |

---

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Deep health check (DB, uptime, channel capacity) |
| GET | `/api/metrics` | JSON counters |
| GET | `/metrics` | Prometheus text exposition |
| GET | `/api/messages` | Search: `?limit=&call_id=&agent=&method=&transport=&src=` |
| GET | `/api/messages/:id` | Single message |
| GET | `/api/report/summary` | Totals, methods, transports |
| GET | `/api/report/kpi` | ASR, NER, registration stats |
| GET | `/api/report/response-codes` | Status code distribution |
| GET | `/api/report/top-calls` | Busiest Call-IDs |
| GET | `/api/report/top-talkers` | Busiest endpoints |
| GET | `/api/report/agents` | HEP node inventory |
| GET | `/api/report/daily` | Daily rollup |
| GET | `/api/report/cps` | Calls per minute: `?minutes=` |
| GET | `/api/realtime` | Live windowed stats: `?window=` (minutes) |
| GET | `/api/nodes` | Per-agent health with status dots |
| GET | `/api/anomalies` | Active anomaly indicators |
| GET | `/api/qos` | QoS/MOS for a call: `?call_id=` |
| GET | `/api/sla/agents` | Per-agent SLA metrics |
| GET | `/api/sla/destinations` | Per-destination SLA metrics |
| GET | `/api/related` | B2BUA correlated calls: `?call_id=` |
| GET | `/api/export` | JSON export with filters |
| POST | `/api/probe` | OPTIONS RTT test |
| POST | `/api/delete` | Bulk delete: `{"call_id":"X"}` or `{"before_ts":N}` |
| POST | `/api/federation/push` | Accept captures from remote instances |
| GET | `/api/federation/health` | Federation connectivity check |
| GET | `/api/grafana/` | Grafana datasource health |
| GET | `/api/grafana/search` | Available Grafana metrics |
| POST | `/api/grafana/query` | Grafana time-series query |

---

## Project layout

```
zaman/
  core/main.mko           # SIP capture, HEP, echo, API, metrics, QoS
  web/main.weft            # dashboard, RBAC, alerting, SLA
  install.sh               # universal Linux installer (Debian + RHEL)
  Dockerfile               # multi-stage container build
  docker-compose.yml       # profiles: default (SQLite), pg, ch
  deploy/
    zaman-core.service     # systemd unit (security-hardened)
    zaman-web.service      # systemd unit
    install.sh             # bare-metal post-build installer
  scripts/
    smoke.sh               # end-to-end test suite
    demo.sh                # local demo (core + dashboard)
    zaman-cli.sh           # CLI: search, export, ladder, kpi
    send_hep.py            # HEP test client (UDP/TCP/TLS)
    send_options.py        # SIP OPTIONS test client
    gen_pcap.py            # PCAP generation from JSON
  docs/
    DEPLOYMENT.md          # sizing, architecture, cloud, checklists
  spec.md                  # engineering spec
  SECURITY_REVIEW.md       # threat model and hardening
```

## License

Apache-2.0
