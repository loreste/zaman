# Zaman

Zaman is a SIP and HEP monitoring stack built with Makori and Weft. It captures
SIP signaling, receives HEP3 from SIP infrastructure, stores the data, and
serves a realtime operations UI for troubleshooting calls, peers, KPIs, reports,
SLA, and alerts.

**Status: v0.3.** Production-track. The current release focuses on realtime
visibility, PostgreSQL-ready deployments, active calls, dedicated SIP ladders,
IP history, report exports, and RBAC-backed operations.

No deployment-specific hosts, keys, or server names are required in source. Use
environment variables, `/etc/zaman/*.env`, nginx, and runtime labels for local
site-specific configuration.

---

## Install

```bash
# Linux (Debian/Ubuntu/RHEL/CentOS/Fedora/Rocky/Alma)
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo bash
```

The installer detects the distro, installs dependencies, builds the core and
web services, configures systemd, optionally sets up PostgreSQL, and can place
nginx in front of the dashboard for ports 80 and 443.

Non-interactive examples:

```bash
# Lab mode: SQLite, no TLS
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo ZAMAN_DB=sqlite bash

# Production mode: PostgreSQL and HTTPS
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo ZAMAN_DB=postgres ZAMAN_TLS=1 ZAMAN_DOMAIN=your-dashboard-domain bash
```

Docker:

```bash
docker compose up                     # SQLite
ZAMAN_PG_PASSWORD='change-me' docker compose --profile pg up  # PostgreSQL
docker compose --profile ch up        # ClickHouse
```

Manual build:

```bash
make build
./scripts/demo.sh
```

Manual builds require Makori >= 0.6.24 and Weft >= 0.6.0.

---

## What It Does

**Capture.** Receives SIP over UDP and HEPv3 over UDP, TCP, and TLS. It parses
SIP requests and responses, redacts sensitive auth headers, and stores capture
records with Call-ID, source/destination, CSeq, method, status, transport, HEP
agent, timestamps, and raw SIP payload.

**Realtime overview.** Shows live CPS, concurrent calls, message rate, attempts,
failures, ASR, node health, live feed, active calls, recent sites, charts, and
notifications. Realtime counters are based on recent capture windows rather
than all-history totals.

**Messages.** Groups messages by Call-ID, supports drilldown to all messages for
that call, and filters by Call-ID, method, transport, HEP agent, IP address,
from number, to number, status, and timestamp/date range.

**SIP ladder.** `/ladder?call_id=...` opens a dedicated ladder page for a single
Call-ID. The page includes summary facts, PCAP export, media/recording controls,
a chronological SIP table, directional ladder visualization, related call legs,
and links to raw SIP messages.

**Calls.** `/calls` is the operations view for realtime call activity. It shows
active calls, CPS, concurrent calls, attempts, failures, recent dialogs, source
and destination IPs, and quick links into messages and the dedicated ladder.

**IP history.** `/ip` searches historical SIP/HEP records by source or
destination IP. Operators can label peers, carriers, customers, sites, and SIP
nodes at runtime without hardcoding those names in source.

**Reports.** `/report` supports filtered report building across messages, calls,
methods, transports, agents, IPs, numbers, status codes, and time ranges. Reports
include telecom KPIs, ASR/NER, response-code breakdowns, source/destination IP
breakdowns, routes, top talkers, agents, daily rollups, and CSV/JSON export.

**Metrics and SLA.** `/metrics` exposes operational breakdowns, source and
destination analysis, Prometheus guidance, CPS, concurrent calls, response
codes, and node health. `/sla` tracks service levels with configurable targets
for availability, ASR, failures, CPS, and destinations.

**Auth and audit.** Dashboard RBAC supports admin, operator, and viewer roles.
The app includes signed sessions, API tokens, rate limits, optional IP
allowlisting, LDAP bind proxy support, and audit trails.

**Alerts.** Operators can configure Slack, webhook, and email notifications for
SIP and platform conditions such as low ASR, timeout spikes, 4xx/5xx errors,
node degradation, high CPS, and auth failures.

---

## Database

| Backend | When to use it | Config |
|---------|----------------|--------|
| SQLite | Lab, demos, single-node small deployments | default |
| PostgreSQL | Production deployments and persistent history | `ZAMAN_DB_DRIVER=postgres` |
| ClickHouse | Very high volume or long retention | `ZAMAN_DB_DRIVER=clickhouse` |

Tables and indexes are created on startup. Retention is controlled by
`ZAMAN_DB_RETENTION_DAYS`, defaults to 14 days, and applies to raw captures,
call summaries, and daily rollups.

---

## Key Routes

| Route | Purpose |
|-------|---------|
| `/` | Realtime overview dashboard |
| `/noc` | HEP/SIP node health and server naming |
| `/messages` | Message search, grouping, and export |
| `/messages/:id` | Raw SIP message detail |
| `/ladder?call_id=...` | Dedicated SIP ladder for one Call-ID |
| `/calls` | Realtime and historical call operations |
| `/ip` | IP history, labels, source/destination analysis |
| `/metrics` | Operational metrics and Prometheus guidance |
| `/report` | Report builder, telecom KPIs, export |
| `/sla` | SLA targets and service-level reporting |
| `/alerts` | Alert rules, channels, and history |
| `/admin/users` | RBAC user management |
| `/admin/tokens` | API token management |
| `/admin/audit` | Audit log |

---

## Configuration

Core settings are environment variables or CLI arguments. Common variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `ZAMAN_DB_DRIVER` | `sqlite` | `sqlite`, `postgres`, or `clickhouse` |
| `ZAMAN_DB_DSN` | backend-specific | SQL database connection string |
| `ZAMAN_SIP_PORT` | `5060` | SIP UDP listen port |
| `ZAMAN_HEP_PORT` | `9060` | HEP UDP listen port |
| `ZAMAN_API_PORT` | `9090` | Core API port |
| `ZAMAN_API_KEY` | empty | Require API key when set |
| `ZAMAN_HEP_PASSWORD` | empty | Optional HEP auth check |
| `ZAMAN_HEP_ALLOW` | empty | Optional HEP peer allowlist |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP over TLS |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | SIP methods to echo |
| `ZAMAN_PROBE` | `0` | Enable active probe API |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete old captures, call summaries, and rollups |

Dashboard settings live in the web environment and runtime JSON state. Labels
for nodes and IPs are managed from the UI and are not committed to source.

---

## Project Layout

```text
zaman/
  core/main.mko           # zaman-core: capture, HEP, echo, API, DB, metrics
  web/main.weft           # zaman-web: dashboard, RBAC, reports, ladder, alerts
  install.sh              # Linux installer
  Dockerfile              # multi-stage container build
  docker-compose.yml      # SQLite / PostgreSQL / ClickHouse profiles
  deploy/                 # systemd units and deployment helpers
  scripts/                # smoke tests, demo, CLI, SIP/HEP clients
  docs/MODULE_SPLIT.md    # planned Makori/Weft module boundaries
  docs/DEPLOYMENT.md      # deployment guide
  spec.md                 # engineering spec
  SECURITY_REVIEW.md      # threat model and hardening status
```

---

## Validation

```bash
make check
make test
```

Useful direct checks:

```bash
makori check core/main.mko
weft check web/main.weft
./scripts/smoke.sh
```

---

## Production Notes

- Local passwords use versioned, per-user salted HMAC-SHA256 key stretching with
  constant-time verification. Legacy hashes are upgraded after successful login.
- Session signing secrets are persisted in the runtime data directory so users
  are not logged out on every restart.
- ClickHouse uses the HTTP SQL interface; string filters are quoted/escaped and
  numeric filters are parsed before query construction.
- RTP audio reconstruction is intentionally not a full media recorder. SIP PCAP
  export is supported, and audio playback depends on captured or uploaded media
  artifacts.
- Carrier-scale sizing should be validated with the target call volume,
  retention period, database backend, and storage profile.

See [SECURITY_REVIEW.md](SECURITY_REVIEW.md) for the current hardening status.

## License

Apache-2.0
