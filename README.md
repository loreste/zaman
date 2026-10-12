# Zaman

Zaman is a SIP and HEP monitoring stack built in Go. It captures SIP signaling,
receives HEP3 from SIP infrastructure, stores the data in PostgreSQL, and
serves a realtime operations dashboard for troubleshooting calls, carriers,
KPIs, reports, SLA, and alerts.

**Status: v0.4.** Production. Go core with batch writes (460+ msg/s), SPA
dashboard with 17 pages, 39 API endpoints, carrier scorecards, GeoIP, SVG
SIP ladder, PCAP export, webhook alerts, and RBAC.

No deployment-specific hosts, keys, or server names are required in source.
Use environment variables, `/etc/zaman/*.env`, nginx, and runtime labels for
local site-specific configuration.

---

## Install

```bash
# Linux (Debian/Ubuntu/RHEL/CentOS/Fedora/Rocky/Alma)
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo bash
```

The installer detects the distro, installs Go, builds both binaries, configures
systemd, and optionally sets up PostgreSQL and nginx.

Docker:

```bash
docker compose up
ZAMAN_PG_PASSWORD='change-me' docker compose --profile pg up  # PostgreSQL
```

Manual build (requires Go >= 1.22):

```bash
make build
# Produces bin/zaman-core and bin/zaman-web
```

---

## What It Does

**Capture.** Receives SIP over UDP and HEPv3 over UDP, TCP, and TLS. Parses
SIP requests and responses, redacts credentials, and stores records with
Call-ID, source/destination, CSeq, method, status, transport, HEP agent,
timestamps, and base64-encoded raw SIP payload.

**Overview.** Live CPS, concurrent calls, ASR, message rate, failures, traffic
charts, node health, and recent call feed. Auto-refreshes every 5 seconds.

**Messages.** Search by Call-ID, method, status code, IP address, from/to
number, time range, and regex. Saved searches. CSV export. Quick filter presets
for common error codes.

**SIP ladder.** Interactive SVG call flow with colored directional arrows,
hover highlighting, click-to-view raw SIP, PCAP export (Ethernet + IPv4 + UDP
with valid checksums), JSON export, and shareable URLs. Live refresh for
active calls. QoS/MOS display when RTCP data is available. SDP/codec/SRTP
detection. Related B2BUA leg correlation (3 methods: HEP correlation ID,
From/To match, reversed From/To).

**Calls.** Search by source/destination IP, caller, callee, status code, and
call state. Carrier analysis tab with per-destination ASR/ACD/failure codes.

**IP history.** Search any IP to see traffic summary, ASR/ACD, method
breakdown, GeoIP location with map (city, ISP, AS number), and carrier
scorecard with 60-minute trend chart.

**Number lookup.** Search by phone number to see call history, ASR, ACD, and
per-call state across all servers.

**NOC.** Server health table with custom naming, associated IPs, status dots,
active call counts, and error highlighting. Click a server name to rename it.

**Reports.** KPIs (concurrent, ASR, ACD, failures), ASR/ACD hourly trend
chart, call volume stacked bar chart, per-server traffic breakdown with share
bars, top talkers with volume bars, request method distribution, response code
classes, and top calls by message count.

**Metrics.** Ingest health (messages, DB writes, errors, uptime), CPS-over-time
line chart, response code distribution, and HEP protocol breakdown table.

**SLA.** Configurable target gauges (ASR, NER, error rate, ACD) with met/at-risk/
breach status. Per-server SLA table. Error breakdown (403, 404, 486, 503, 5xx).
Per-destination and per-source IP tables with ASR and ACD.

**Alerts.** Live anomaly detection (auth failures, 5xx errors, 486 spikes).
Response code distribution. Configurable webhook URLs and threshold settings.
Background alert worker fires webhooks every 60 seconds for critical anomalies.

**Probe.** Send SIP OPTIONS to test endpoint reachability. Displays RTT, status
code, and result. Keeps a session history of recent probes.

**Wallboard.** Full-screen NOC mode with 4 large KPIs and 6 secondary metrics.
Auto-refreshes every 3 seconds. Press `w` from any page to enter.

**Settings.** API key management, user administration (add/delete/reset password,
role assignment), and system health display.

---

## Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌────────────┐
│  SIP/HEP    │────▶│  zaman-core  │────▶│ PostgreSQL │
│  sources    │     │  (Go binary) │     │            │
└─────────────┘     └──────┬───────┘     └────────────┘
                           │ :9090
                    ┌──────┴───────┐
                    │  zaman-web   │
                    │  (Go binary) │
                    │  :3000       │
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │    nginx     │
                    │  :443 (TLS)  │
                    └──────────────┘
```

- **zaman-core** — SIP/HEP capture, PostgreSQL batch writer, 39-endpoint REST
  API, 3-second cache worker, anomaly detection, webhook alerts, SIP probe.
- **zaman-web** — Go reverse proxy with cookie-based auth, HMAC sessions, user
  management, node naming, saved searches, per-user preferences. Serves the SPA.
- **SPA** — Single-page app (vanilla JS, Tailwind CSS, Chart.js, Leaflet) with
  17 pages and client-side routing.

---

## Database

| Backend | Status | Config |
|---------|--------|--------|
| PostgreSQL | Production | `ZAMAN_DB_DRIVER=postgres` |

Tables and indexes are created on startup. Retention is controlled by
`ZAMAN_DB_RETENTION_DAYS` (default 14). The core drops old partitions hourly
and cleans call_state every 15 minutes.

Recommended PostgreSQL tuning for 8 GB RAM:
```
shared_buffers = 2GB
work_mem = 64MB
maintenance_work_mem = 512MB
effective_cache_size = 6GB
```

---

## Key Routes

| Route | Purpose |
|-------|---------|
| `/#/` | Overview dashboard |
| `/#/noc` | Server health and naming |
| `/#/messages` | Message search with filters and time ranges |
| `/#/ladder?call_id=...` | Interactive SIP ladder with PCAP export |
| `/#/calls` | Call search and carrier analysis |
| `/#/ip?addr=...` | IP history with GeoIP map and carrier scorecard |
| `/#/number?q=...` | Phone number lookup |
| `/#/metrics` | System metrics and CPS charts |
| `/#/reports` | Traffic reports and KPI trends |
| `/#/sla` | SLA gauges and per-IP breakdown |
| `/#/alerts` | Anomaly detection and webhook config |
| `/#/probe` | SIP OPTIONS probe |
| `/#/wallboard` | Full-screen NOC display |
| `/#/admin` | User management and settings |

---

## API Endpoints

All endpoints are JSON. Authentication via `X-API-Key` header or `Authorization: Bearer` token.

| Path | Method | Purpose |
|------|--------|---------|
| `/api/health` | GET | Health check (detailed if authenticated) |
| `/api/realtime` | GET | Live stats (window, agent params) |
| `/api/nodes` | GET | Per-agent health |
| `/api/messages` | GET | Message search (call_id, method, status, ip, time range, regex) |
| `/api/messages/{id}` | GET | Single message by ID |
| `/api/calls/active` | GET | Active calls (src, dst, from_number, to_number, state) |
| `/api/report` | GET | Report summary |
| `/api/report/daily` | GET | Daily method breakdown |
| `/api/report/top-calls` | GET | Top calls by traffic |
| `/api/report/top-talkers` | GET | Top source IPs |
| `/api/report/agents` | GET | Per-agent summary |
| `/api/report/response-codes` | GET | SIP status code distribution |
| `/api/report/cps` | GET | Calls per minute timeline |
| `/api/report/kpi` | GET | Key performance indicators |
| `/api/sla/agents` | GET | SLA by agent |
| `/api/sla/destinations` | GET | Per-destination ASR/ACD |
| `/api/sla/sources` | GET | Per-source ASR/ACD |
| `/api/sla/carrier` | GET | Carrier scorecard with trend |
| `/api/trend/hourly` | GET | Hourly ASR/ACD/volume |
| `/api/trend/daily` | GET | Daily ASR/ACD/volume |
| `/api/anomalies` | GET | Active anomaly alerts |
| `/api/related` | GET | B2BUA correlated calls |
| `/api/number` | GET | Phone number lookup |
| `/api/geoip` | GET | IP geolocation |
| `/api/qos` | GET | Call quality metrics (RTCP) |
| `/api/export` | GET | Message export (JSON) |
| `/api/export/csv` | GET | Message export (CSV) |
| `/api/probe` | POST | SIP OPTIONS probe |
| `/api/delete` | POST | Delete by call_id or timestamp |
| `/api/alerts/config` | GET/POST | Webhook alert configuration |
| `/api/federation/health` | GET | Federation status |
| `/metrics` | GET | Prometheus exposition format |

---

## Configuration

Core settings via environment variables or CLI args (`[sip_port] [hep_port] [api_port]`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZAMAN_DB_DRIVER` | `postgres` | Database backend |
| `ZAMAN_DB_DSN` | `host=localhost dbname=zaman sslmode=disable` | PostgreSQL connection |
| `ZAMAN_SIP_PORT` | `5060` | SIP UDP listen port |
| `ZAMAN_HEP_PORT` | `9060` | HEP UDP listen port |
| `ZAMAN_API_PORT` | `9090` | Core API port |
| `ZAMAN_API_KEY` | empty | API authentication token |
| `ZAMAN_HEP_PASSWORD` | empty | HEP packet auth |
| `ZAMAN_HEP_ALLOW` | empty | HEP peer IP allowlist (comma-separated) |
| `ZAMAN_HEP_TCP` | `0` | Enable HEP/TCP listener |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP/TLS listener |
| `ZAMAN_HEP_TLS_CERT` | empty | TLS certificate path |
| `ZAMAN_HEP_TLS_KEY` | empty | TLS key path |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | SIP methods to echo (or `ALL`) |
| `ZAMAN_PROBE` | `0` | Enable SIP probe endpoint |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete old data |
| `ZAMAN_RATE_LIMIT` | `100` | Max API requests/sec per IP |
| `ZAMAN_CONCURRENT_CALL_MAX_AGE_SEC` | `7200` | Answered call age threshold |
| `ZAMAN_CONCURRENT_RINGING_MAX_AGE_SEC` | `300` | Ringing call age threshold |
| `ZAMAN_STATIC_DIR` | `web/static` | SPA static file directory |
| `ZAMAN_TRUSTED_PROXY` | empty | IP allowed to set X-Forwarded-For |

Web dashboard settings:

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZAMAN_CORE` | `http://127.0.0.1:9090` | Core API URL |
| `ZAMAN_WEB_PORT` | `3000` | Dashboard listen port |
| `ZAMAN_AUTH` | `1` | Enable auth (`0` to disable) |
| `ZAMAN_DATA_DIR` | `data` | User/session/config data directory |

---

## Project Layout

```text
zaman/
  core-go/              # zaman-core: Go SIP/HEP capture, API, DB
    main.go             # entry point, config, worker orchestration
    sip.go              # SIP parsing, echo, SDP extraction
    hep.go              # HEP3 decoder, UDP/TCP/TLS listeners
    db.go               # PostgreSQL schema, batch inserts, retention
    api.go              # HTTP routes, auth, rate limiting
    cache.go            # 3-second cache refresh worker
    reports.go          # KPI, realtime, agents, trends, SQL builders
    probe.go            # SIP OPTIONS probe
    qos.go              # RTCP/RTP parsing, MOS calculation
    alerts.go           # Webhook alert worker
  web/                  # zaman-web: Go dashboard proxy
    main.go             # auth, reverse proxy, user management
    static/index.html   # SPA shell
    static/app.js       # dashboard SPA (17 pages)
  deploy/               # systemd units
  scripts/              # smoke tests, demo
  install.sh            # Linux installer
  Dockerfile            # multi-stage container build
  docker-compose.yml    # PostgreSQL profile
```

---

## Build

```bash
make build              # builds bin/zaman-core and bin/zaman-web
make check              # go vet on both modules
```

Cross-compile for Linux:

```bash
cd core-go && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/zaman-core .
cd web && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../bin/zaman-web .
```

---

## Production Notes

- Batch DB writer processes 100 records per transaction at 200ms flush intervals.
  Handles 460+ messages/second with zero drops.
- HMAC-SHA256 session tokens with 25,000-round password hashing and per-user salts.
  Session secrets persist across restarts.
- API rate limiting at 100 req/sec per IP (configurable). Constant-time key comparison.
- HEP peer allowlisting and password authentication with constant-time comparison.
- SIP credentials (Authorization headers) redacted before storage.
- PCAP export produces valid Ethernet + IPv4 + UDP frames with computed checksums.
  Opens directly in Wireshark with full SIP protocol dissection.
- B2BUA correlation uses three methods: HEP correlation ID, From/To header match
  within 30 seconds, and reversed From/To match.
- Recommended: UFW firewall blocking ports 3000 and 9090 externally, nginx on 443.
- Recommended: daily pg_dump backup cron, 7-day rotation.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` | Jump to message search |
| `w` | Enter wallboard mode |
| `Esc` | Close detail panels |

## License

Apache-2.0
