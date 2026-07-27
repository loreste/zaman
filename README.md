# Zaman

SIP monitoring for people who are tired of running five systems to answer one question.

## Why this exists

If you run a VoIP network, you probably have one tool for SIP capture, another for metrics, another for dashboards, some scripts for keepalive checks, and maybe a wiki page explaining how they all connect. Each tool is fine on its own. The problem is gluing them together, keeping them running, and training new engineers on four different UIs.

Zaman started as a question: what if one process did all of that? Not better than each tool individually — just simpler to deploy and operate as a whole.

It captures SIP and HEP traffic, stores it in SQLite (or PostgreSQL), shows a live dashboard with call ladders, and exposes Prometheus-compatible metrics. One binary for the core, one process for the dashboard. No external databases required unless you want them.

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

**Capture:** SIP over UDP, HEPv3 over UDP/TCP/TLS. Compatible with any HEP-speaking SIP proxy or agent.

**Dashboard:** Real-time NOC overview with active calls, ASR/NER gauges, per-node health grid, anomaly detection. HTMX live-refresh, no JavaScript frameworks.

**Call ladder:** SIP flow diagrams with directional arrows between endpoints. PCAP export for Wireshark. Call recording upload and playback.

**Search:** Filter by Call-ID, agent/server, SIP method, transport, endpoint IP. Save searches. Export as JSON or CSV.

**Reports:** Telecom KPIs (ASR, NER), response code breakdown, top talkers, agent inventory, daily rollups, SLA dashboard.

**Alerting:** Threshold rules on ASR, error rates, 5xx spikes, auth failures. Notify via Slack, generic webhook, or email.

**Auth:** Role-based access — admin, operator, viewer. API tokens for automation. Audit log. Password policy. IP allowlisting.

**Metrics:** Prometheus-compatible `/metrics` endpoint on the core.

## Quick start

Requirements: [Mako](https://mako-lang.dev) ≥ 0.4.17 and [Weft](https://weft.dev) on PATH.

```bash
make build          # → bin/zaman-core
make smoke          # end-to-end test (high ports, no root)
./scripts/demo.sh   # core + dashboard → http://127.0.0.1:3000
```

Manual run:

```bash
# terminal 1 — core
./bin/zaman-core 15060 19060 19090

# terminal 2 — dashboard
ZAMAN_CORE=http://127.0.0.1:19090 weft run web/main.weft
```

On first start with auth enabled, the dashboard prints a default admin password to stdout. Change it immediately.

### Docker

```bash
# SQLite (simplest)
docker compose up

# With PostgreSQL
docker compose --profile pg up

# With ClickHouse (for scale)
docker compose --profile ch up
```

### Systemd (bare metal)

```bash
make build
sudo bash deploy/install.sh
sudo systemctl enable --now zaman-core zaman-web
```

Config: `/etc/zaman/core.env` and `/etc/zaman/web.env`. Logs: `journalctl -u zaman-core`.

## Database

Three backends, depending on scale:

| Backend | Best for | Config |
|---------|----------|--------|
| **SQLite** | Single instance, lab, small deployments | default — zero config |
| **PostgreSQL** | Production with existing Postgres infrastructure | `ZAMAN_DB_DRIVER=postgres` |
| **ClickHouse** | High volume — millions of calls/day, long retention | `ZAMAN_DB_DRIVER=clickhouse` |

```bash
# SQLite (default — zero config)
./bin/zaman-core

# PostgreSQL
ZAMAN_DB_DRIVER=postgres \
  ZAMAN_DB_DSN="host=localhost dbname=zaman user=zaman password=secret sslmode=disable" \
  ./bin/zaman-core

# ClickHouse (for scale)
ZAMAN_DB_DRIVER=clickhouse \
  ZAMAN_CH_URL=http://localhost:8123 \
  ZAMAN_CH_DB=zaman \
  ./bin/zaman-core
```

Tables are auto-created on first run for all backends.

**ClickHouse notes:** Uses MergeTree engine partitioned by month, ordered by `(ts_ms, call_id)` for fast time-range and call-correlation queries. The daily rollup table uses SummingMergeTree for automatic counter aggregation. Communication is via ClickHouse's HTTP interface — no native driver needed. Designed for append-heavy workloads with millions of rows per day.

## HEP

Native HEPv3 collector. Point your existing SIP proxies at Zaman's HEP port and it works.

| Transport | Default | Enable |
|-----------|---------|--------|
| UDP | `:9060` | always on |
| TCP | `:9062` | `ZAMAN_HEP_TCP=1` |
| TLS | `:9061` | `ZAMAN_HEP_TLS=1` + cert/key |

Optional HEP password and peer IP allowlisting are supported.

## Echo

Inbound SIP is always captured. By default, Zaman replies to OPTIONS with 200 OK (useful for keepalive monitoring). REGISTER always gets 401 — it never pretends to be a registrar.

## Dashboard pages

| Page | What it shows |
|------|--------------|
| **Overview** | Real-time NOC view — active calls, ASR, error rate, node health grid, anomaly alerts, live capture feed |
| **Messages** | Full search with saved filters, JSON/CSV/PCAP export |
| **Call ladder** | SIP flow diagram with arrows, recording playback, PCAP download, share link |
| **Probe** | Active OPTIONS RTT test (operator+ role) |
| **Metrics** | Charts + Prometheus scrape config |
| **Reports** | ASR/NER gauges, response codes, top talkers, agents, daily rollups |
| **Alerts** | Threshold rules, Slack/webhook/email channels, alert history |
| **SLA** | Service level dashboard with availability status |
| **Users** | Admin: create/delete users, assign roles |
| **API Tokens** | Admin: generate/revoke Bearer tokens for automation |
| **Audit Log** | Admin: who logged in, who changed what |

## Auth and access control

Three roles: **admin** (full access), **operator** (+ probe, alerts), **viewer** (read-only dashboard).

Set `ZAMAN_AUTH=0` to disable auth entirely for lab use.

API tokens can be generated from the admin panel for scripts and CI pipelines. Use as `Authorization: Bearer <token>`.

IP allowlisting: set `ZAMAN_DASHBOARD_ALLOW_IPS=10.0.0.,192.168.1.` to restrict dashboard access.

## Core API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Liveness (always open) |
| GET | `/api/metrics`, `/metrics` | JSON counters, Prometheus text |
| GET | `/api/messages?limit=&call_id=&agent=&method=&transport=&src=` | Search captures |
| GET | `/api/messages/:id` | Single message |
| GET | `/api/report/summary` | Totals, methods, transports |
| GET | `/api/report/kpi` | ASR, NER, registration stats |
| GET | `/api/report/response-codes` | Status code distribution |
| GET | `/api/report/top-calls` | Busiest Call-IDs |
| GET | `/api/report/top-talkers` | Busiest endpoints |
| GET | `/api/report/agents` | HEP node inventory |
| GET | `/api/report/daily` | Daily rollup |
| GET | `/api/report/cps?minutes=` | Calls per minute |
| GET | `/api/realtime?window=` | Windowed stats (default 5 min) |
| GET | `/api/nodes` | Per-agent health with status |
| GET | `/api/anomalies` | Active anomaly indicators |
| POST | `/api/probe` | OPTIONS RTT test |

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
| `ZAMAN_LDAP_URL` | _(empty)_ | LDAP HTTP bind proxy URL for auth |
| `ZAMAN_CORE` | `http://127.0.0.1:9090` | Core URL (for dashboard) |

## Integrations

**Grafana:** The core exposes a JSON datasource at `/api/grafana/`. Point Grafana's SimpleJSON datasource at `http://zaman-core:9090/api/grafana/` for metrics.

**LDAP/SSO:** Set `ZAMAN_LDAP_URL` to an LDAP HTTP bind proxy. Zaman POSTs `{"username","password"}` and expects `{"ok":true,"role":"..."}`. Falls back to local users if LDAP is unavailable.

**Prometheus:** Scrape `/metrics` on the core port. Standard text exposition format.

## Project layout

```
zaman/
  core/main.mko          # capture, echo, HEP, API, metrics (Mako)
  web/main.weft           # dashboard, auth, alerting (Weft + HTMX)
  Dockerfile              # multi-stage build
  docker-compose.yml      # SQLite / PostgreSQL / ClickHouse profiles
  deploy/
    zaman-core.service    # systemd unit
    zaman-web.service     # systemd unit
    install.sh            # bare-metal installer
  scripts/
    smoke.sh              # end-to-end test
    demo.sh               # local demo
    send_hep.py           # HEP test client
    send_options.py       # SIP OPTIONS test client
    gen_pcap.py           # PCAP generation
  spec.md                 # engineering spec
  SECURITY_REVIEW.md      # threat model
```

## Scale

Zaman is designed to run at two speeds:

- **Small**: SQLite, single binary, laptop or VM. Thousands of calls/day. No dependencies.
- **Large**: ClickHouse backend, millions of calls/day, months of retention. Same binary, different env var.

The core writes captures through a single serialized channel (`chan[string]` → `db_writer`). The channel capacity (`DB_CH_CAP=1024`) provides backpressure when the database lags. For ClickHouse deployments, this is append-only with no UPDATE overhead — each capture is a single INSERT.

The dashboard is stateless (HMAC-signed cookies, no server-side sessions). You can run multiple dashboard instances behind a load balancer against the same core.

## Limitations

Some things Zaman does not do today:

- No RTP/media capture or MOS scoring (SIP signaling only)
- No multi-node federation (single core instance)
- No built-in TLS on the dashboard (use a reverse proxy)
- Alert evaluation is poll-based (30s), not streaming
- The UI is server-rendered with HTMX — no client-side SPA
- ClickHouse batch inserts are per-row over HTTP; for maximum throughput at extreme scale, a batching proxy (e.g. `clickhouse-bulk`) can sit between Zaman and ClickHouse

## License

Apache-2.0
