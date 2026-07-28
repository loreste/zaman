# Zaman — Product & Engineering Spec

**Status:** v0.2 (production-track)  
**Stack:** Mako core (`core/main.mko`) + Weft dashboard (`web/main.weft`)  
**Verified on:** Mako ≥ **0.4.18**, Weft ≥ **0.3.30**  
**License:** Apache-2.0

This document is the source of truth. When behaviour is ambiguous, spec wins over README.

---

## 1. What Zaman is

Integrated SIP monitoring: capture, metrics, dashboards, alerting, and echo — one process pair, no external dependencies unless you want them.

### 1.1 Goals

1. Capture native SIP (UDP) and HEPv3 (UDP / TCP / TLS).
2. Echo monitoring pings safely (default: OPTIONS → 200 only).
3. Durable storage with three backend options: SQLite, PostgreSQL, ClickHouse.
4. Real-time NOC dashboard with telecom KPIs (ASR, NER), time-series charts, anomaly detection.
5. SIP call ladder with PCAP export, recording upload/playback, share links, B2BUA correlation.
6. RTCP parsing with QoS metrics (jitter, loss, R-factor, MOS via ITU-T G.107).
7. RBAC (admin / operator / viewer), API tokens, audit log, LDAP/SSO.
8. Alerting via Slack, generic webhook, email with retry.
9. Multi-node federation (remote instances push to central aggregator).
10. Per-agent and per-destination SLA tracking with configurable thresholds.
11. Prometheus-compatible `/metrics` endpoint and Grafana datasource API.
12. Dashboard TLS via nginx reverse proxy (auto-configured by installer).
13. Structured concurrency via Mako `crew` / `kick` / `chan`.

### 1.2 Non-goals

- Full RTP media stream capture (RTCP quality metrics are supported, raw RTP is not).
- Client-side SPA (server-rendered HTMX).

---

## 2. Repository layout

```
zaman/
  spec.md               # this document
  README.md             # operator-facing docs
  SECURITY_REVIEW.md    # threat model + hardening
  LICENSE               # Apache-2.0
  Makefile              # build / smoke / demo / doctor
  mako.toml             # Mako package manifest
  main.mko              # stub → build core/
  core/
    main.mko            # zaman-core (capture, echo, HEP, API, DB)
  web/
    main.weft           # zaman-web (dashboard, auth, alerting)
    public/             # static assets (favicon)
  scripts/
    smoke.sh            # e2e SIP / HEP UDP+TCP+TLS / probe / metrics
    demo.sh             # core + web local demo
    send_hep.py         # HEPv3 test client (UDP/TCP/TLS)
    send_options.py     # SIP OPTIONS test client
    gen_pcap.py         # PCAP generation from JSON
  data/                 # runtime (gitignored): DB, users, recordings, alerts
```

---

## 3. Runtime components

### 3.1 zaman-core (Mako)

Single native binary. Captures SIP/HEP, stores to database, serves JSON/Prometheus API.

```bash
mako build --release core/main.mko -o bin/zaman-core
./bin/zaman-core [sip_port] [hep_port] [api_port]
```

Default ports: SIP 5060, HEP 9060, API 9090.

### 3.2 zaman-web (Weft)

HTMX dashboard + auth + alerting. Talks to core via HTTP API.

```bash
ZAMAN_CORE=http://127.0.0.1:9090 weft run web/main.weft
```

Listens on :3000.

---

## 4. Database backends

| Backend | Engine | Best for |
|---------|--------|----------|
| SQLite | WAL mode, single file | Lab, small deployments, zero-config |
| PostgreSQL | `sql_open_postgres` | Production with existing PG infra |
| ClickHouse | HTTP interface, MergeTree | Millions of calls/day, long retention |

Selected via `ZAMAN_DB_DRIVER` (default: `sqlite`).

### 4.1 Schema

**captures** — one row per SIP message:

| Column | Type | Notes |
|--------|------|-------|
| id | integer/snowflake | Auto-generated |
| ts_ms | int64 | Epoch milliseconds |
| src, dst | text | `host:port` |
| transport | text | UDP, HEP3, HEP3/TCP, HEP3/TLS |
| proto | text | sip, rtcp, ... |
| agent | text | HEP node name |
| kind | text | request, response |
| method | text | INVITE, BYE, OPTIONS, ... |
| status | int | SIP response code (0 for requests) |
| call_id | text | SIP Call-ID |
| from_h, to_h, cseq, ruri | text | SIP headers |
| hep_node_id, hep_node, hep_cid | text/int | HEP metadata |
| size | int | Payload length |
| raw_b64 | text | Base64 of redacted SIP |
| record_json | text | Full JSON record |

**report_daily** — day/method/transport counters (SummingMergeTree on ClickHouse).

### 4.2 ClickHouse specifics

- MergeTree partitioned by month, ordered by `(ts_ms, call_id)`.
- Communication via HTTP POST to port 8123.
- Append-only — no UPDATE (each capture is a single INSERT).
- SummingMergeTree for daily rollups (automatic counter merge).

---

## 5. Concurrency model

1. Concurrency uses Mako's structured primitives: `crew`, `kick`, `join`, `drain`, `chan`.
2. Capture producers enqueue JSON via `chan[string]` — they do not open the database directly.
3. A single `db_writer` job owns the database connection (or ClickHouse HTTP client).
4. Optional TCP/TLS collectors are started only when enabled.

---

## 6. Dashboard pages

| Route | Page | Role | Features |
|-------|------|------|----------|
| `/` | Overview | all | NOC view: KPI strip, node health grid, time-series traffic charts (5m/15m/1h/6h/24h/custom), anomaly alerts, live capture feed |
| `/messages` | Messages | all | Multi-field search (Call-ID, agent, method, transport, IP), saved searches, JSON/CSV/PCAP export |
| `/messages/:id` | Message detail | all | Full SIP headers, raw decoded message |
| `/calls` | Call ladder | all | Homer-style arrow diagram, PCAP download, recording player, share link, recent calls sidebar |
| `/probe` | Echo probe | operator+ | Active OPTIONS RTT test against any host |
| `/metrics` | Metrics | all | Charts, Prometheus scrape config |
| `/report` | Reports | all | ASR/NER gauges, response codes, top talkers, agents, daily rollup, method/transport charts |
| `/alerts` | Alerts | operator+ | Alert rules, notification channels (Slack/webhook/email), alert history |
| `/sla` | SLA Report | all | Availability status, ASR gauge, threshold reference |
| `/admin/users` | Users | admin | Create/delete users, assign roles, reset passwords |
| `/admin/tokens` | API Tokens | admin | Generate/revoke Bearer tokens for automation |
| `/admin/audit` | Audit Log | admin | Login attempts, config changes, exports |

---

## 7. Auth

### 7.1 RBAC

| Action | viewer | operator | admin |
|--------|--------|----------|-------|
| Dashboard read | yes | yes | yes |
| Run probe | no | yes | yes |
| Manage alerts | no | yes | yes |
| Manage users, tokens, audit | no | no | yes |

### 7.2 Session tokens

HMAC-SHA256 signed cookies (stateless — no server-side session store). Token contains `id:username:role:expires`. HMAC secret is per-process (restart invalidates all sessions).

### 7.3 API tokens

Long-lived Bearer tokens for automation. Stored as SHA-256 hashes. Generated from admin panel, shown once.

### 7.4 Password policy

Minimum 8 characters, at least one digit.

### 7.5 IP allowlisting

`ZAMAN_DASHBOARD_ALLOW_IPS` — comma-separated IPs/prefixes. Checks `X-Forwarded-For` for reverse proxy setups.

### 7.6 Disable auth

`ZAMAN_AUTH=0` — all routes open, anonymous user gets admin role. Lab only.

---

## 8. Alerting

### 8.1 Channels

- **Slack**: webhook URL, formatted messages with severity icons.
- **Generic webhook**: POST JSON to any URL (PagerDuty, Teams, Opsgenie).
- **Email**: SMTP with configurable host/port.

### 8.2 Rules

Threshold-based on 5-minute windowed metrics: ASR, error rate, 5xx count, 4xx count, 401/403/503 counts, INVITE rate, REGISTER rate, active calls.

Default rules: Low ASR (<40%), High error rate (>15%), 5xx spike (>5), Auth failures (>10), 503 unavailable (>3).

### 8.3 Anomaly detection

Built-in pattern detection (core API `/api/anomalies`): auth failure spikes, registration storms (>50/min), server errors, SIP scanning (>20 distinct Call-IDs from one source in 5 min), busy (486) spikes.

### 8.4 Evaluation

HTMX polls `/partials/alerts` every 30 seconds. Fires matched rules to all configured channels. History persisted to `data/zaman-alert-history.json`.

---

## 9. Core API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | open | Liveness |
| GET | `/api/metrics` | key? | JSON counters |
| GET | `/metrics` | key? | Prometheus text |
| GET | `/api/messages` | key? | Search: `?limit=&call_id=&agent=&method=&transport=&src=` |
| GET | `/api/messages/:id` | key? | Single message |
| GET | `/api/report/summary` | key? | Totals, methods, transports |
| GET | `/api/report/kpi` | key? | ASR, NER, registration stats |
| GET | `/api/report/response-codes` | key? | Status code distribution |
| GET | `/api/report/top-calls` | key? | Busiest Call-IDs |
| GET | `/api/report/top-talkers` | key? | Busiest endpoints |
| GET | `/api/report/agents` | key? | HEP node inventory |
| GET | `/api/report/daily` | key? | Daily rollup |
| GET | `/api/report/cps` | key? | Calls per minute: `?minutes=` |
| GET | `/api/realtime` | key? | Windowed live stats: `?window=` (minutes) |
| GET | `/api/nodes` | key? | Per-agent health with status |
| GET | `/api/anomalies` | key? | Active anomaly indicators |
| GET | `/api/export` | key? | JSON export: `?limit=&call_id=&transport=` |
| POST | `/api/probe` | key? | OPTIONS RTT: `{"host","port","timeout_ms"}` |

---

## 10. Configuration

| Env | Default | Purpose |
|-----|---------|---------|
| `ZAMAN_DB_DRIVER` | `sqlite` | `sqlite`, `postgres`, or `clickhouse` |
| `ZAMAN_DB` | `data/zaman.db` | SQLite path |
| `ZAMAN_DB_DSN` | _(localhost)_ | PostgreSQL connection string |
| `ZAMAN_CH_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `ZAMAN_CH_DB` | `zaman` | ClickHouse database name |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete older captures (0 = keep all) |
| `ZAMAN_SIP_HOST` | `0.0.0.0` | Bind address |
| `ZAMAN_SIP_PORT` / argv1 | `5060` | SIP UDP |
| `ZAMAN_HEP_PORT` / argv2 | `9060` | HEP UDP |
| `ZAMAN_API_PORT` / argv3 | `9090` | HTTP API |
| `ZAMAN_API_KEY` | _(empty)_ | Require key on API (except /health) |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | Which methods get auto-reply |
| `ZAMAN_ECHO_ALL` | `0` | Echo every request (lab only) |
| `ZAMAN_PROBE` | `0` | Enable probe API |
| `ZAMAN_PROBE_ALLOW_PRIVATE` | `0` | Allow probing RFC1918 |
| `ZAMAN_HEP_TCP` | `0` | Enable HEP/TCP |
| `ZAMAN_HEP_TCP_PORT` | `9062` | TCP port |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP/TLS |
| `ZAMAN_HEP_TLS_PORT` | `9061` | TLS port |
| `ZAMAN_HEP_TLS_CERT/KEY` | | PEM paths |
| `ZAMAN_HEP_PASSWORD` | _(empty)_ | HEP auth |
| `ZAMAN_HEP_ALLOW` | _(empty)_ | HEP peer allowlist |
| `ZAMAN_AUTH` | _(enabled)_ | Set `0` to disable dashboard auth |
| `ZAMAN_DASHBOARD_ALLOW_IPS` | _(empty)_ | IP allowlist for dashboard |
| `ZAMAN_CORE` | `http://127.0.0.1:9090` | Core URL (for dashboard) |

---

## 11. Data files (in `data/`, gitignored)

| File | Purpose |
|------|---------|
| `zaman.db` | SQLite database (when using sqlite backend) |
| `zaman-users.json` | User accounts (username, hashed password, role) |
| `zaman-api-tokens.json` | API tokens (SHA-256 hashes, labels) |
| `zaman-alerts.json` | Alert rules and notification channels |
| `zaman-alert-history.json` | Fired alert history (last 100) |
| `zaman-searches.json` | Saved search profiles |
| `zaman-audit.jsonl` | Audit log (append-only JSONL) |
| `recordings/` | Call recordings (WAV/MP3, named by Call-ID) |
| `tls/` | HEP TLS certificates |

---

## 12. Security posture

Authoritative review: `SECURITY_REVIEW.md`.

| Control | Default |
|---------|---------|
| Dashboard auth | RBAC enabled (admin/operator/viewer) |
| Probe API | Off (`ZAMAN_PROBE=1` to enable) |
| Echo | OPTIONS only; REGISTER → 401 |
| Auth headers | Redacted before store/export |
| Probe timeout | ≤ 5s; private ranges blocked by default |
| API key | Optional (`ZAMAN_API_KEY`) |
| HEP password/allowlist | Optional |
| Password policy | Min 8 chars + digit |
| Audit log | All auth/admin actions logged |
| IP allowlisting | Optional (`ZAMAN_DASHBOARD_ALLOW_IPS`) |
| Session tokens | HMAC-signed, 24h expiry, per-process secret |

---

## 13. Build & test

```bash
make doctor   # check toolchain
make build    # → bin/zaman-core
make smoke    # e2e: SIP echo, probe, HEP UDP/TCP/TLS, metrics
make demo     # core + dashboard on high ports
make clean    # rm -rf bin .mako
```
