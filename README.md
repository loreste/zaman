# Zaman

SIP monitoring that installs in one command. Capture, call ladders, metrics,
alerting, and dashboards — one binary pair instead of four separate tools wired
together over a weekend.

Named after the friend who pointed out the obvious: VoIP teams shouldn't need
Homer + Prometheus + Grafana + custom scripts just to see what's happening on
their network.

**Status: v0.2.** Works, handles real traffic, has auth and alerting. Not
battle-tested at carrier scale yet. SQLite out of the box; PostgreSQL and
ClickHouse when you outgrow it.

---

## Install

```bash
# Linux (Debian/Ubuntu/RHEL/CentOS/Fedora/Rocky/Alma)
curl -fsSL https://raw.githubusercontent.com/loreste/zaman/main/install.sh | sudo bash
```

The installer detects your distro, installs dependencies, builds the binary,
sets up systemd services, picks a database, and prints the dashboard URL. It
asks before doing anything destructive. Non-interactive:

```bash
# SQLite, no TLS
curl -fsSL .../install.sh | sudo ZAMAN_DB=sqlite bash

# PostgreSQL with HTTPS
curl -fsSL .../install.sh | sudo ZAMAN_DB=postgres ZAMAN_TLS=1 ZAMAN_DOMAIN=sip.company.com bash
```

Docker:

```bash
docker compose up                     # SQLite
docker compose --profile pg up        # PostgreSQL
docker compose --profile ch up        # ClickHouse
```

Manual build (needs [Mako](https://mako-lang.com) ≥ 0.4.19 and Weft):

```bash
make build && ./scripts/demo.sh       # → http://127.0.0.1:3000
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for sizing, cloud instances, and
post-install checklists.

---

## What it does

**Capture.** SIP over UDP with configurable echo (OPTIONS by default, REGISTER
always returns 401). HEPv3 over UDP, TCP, and TLS — works with Kamailio,
OpenSIPS, FreeSWITCH, heplify, captagent. Auth headers are redacted before
storage.

**Dashboard.** Overview with live KPIs (active calls, ASR, error rate). NOC
view with node health. Message search with multi-field filtering and
JSON/CSV/PCAP export. Call ladders with directional arrows, PCAP download,
recording upload + playback, and shareable links. Probe page for active OPTIONS
RTT tests. Metrics page with Prometheus scrape config. Reports with ASR/NER
gauges, response code breakdown, top talkers, HEP agent inventory, and daily
rollups. SLA tracking per agent and destination. Alert rules with Slack,
webhook, and email delivery.

**QoS.** RTCP packets via HEP are parsed for jitter, packet loss, R-factor
(E-model), and MOS. QoS data is attached to capture records and queryable
via API.

**Federation.** Remote Zaman instances push captures to a central aggregator
over the API.

**Auth.** RBAC with admin/operator/viewer roles. HMAC-SHA256 signed sessions.
API tokens for automation. Rate limiting. IP allowlisting. Audit log. LDAP
bind proxy for SSO.

---

## Database

| Backend | When to use it | Config |
|---------|---------------|--------|
| SQLite | Lab, single instance, small deployments | default — nothing to configure |
| PostgreSQL | Production, existing Postgres | `ZAMAN_DB_DRIVER=postgres` |
| ClickHouse | High volume, long retention | `ZAMAN_DB_DRIVER=clickhouse` |

Tables and indexes are created on first run. Schema is the same across all
three backends. Retention is configurable (`ZAMAN_DB_RETENTION_DAYS`, default
14).

---

## Concurrency

The core uses Mako's structured concurrency — `crew` / `kick` / `chan`. Workers
for SIP, HEP (UDP/TCP/TLS), and HTTP are kicked from one crew block. A single
`db_writer` drains a typed string channel (`for j in range ch`) and owns the
database connection. TLS sessions run inline (handshake serialized, then
read → close → parse) to avoid OpenSSL threading issues.

No goroutines, no free threads, no thread pools. Every spawned task has an
owner.

---

## API

The core exposes a JSON API on port 9090 (configurable). All endpoints except
`/health` require an API key when `ZAMAN_API_KEY` is set.

Health, metrics, message search, single message, report summary, KPIs,
response codes, top calls, top talkers, agent inventory, daily rollup, CPS,
realtime window, node health, anomalies, QoS, SLA, related calls, export,
probe, bulk delete, federation push/health, and Grafana datasource.

Full endpoint list in the [spec](spec.md).

---

## Configuration

Core settings via environment variables or CLI args. Key ones:

| Variable | Default | What it does |
|----------|---------|-------------|
| `ZAMAN_DB_DRIVER` | `sqlite` | Database backend |
| `ZAMAN_SIP_PORT` | `5060` | SIP UDP listen port |
| `ZAMAN_HEP_PORT` | `9060` | HEP UDP listen port |
| `ZAMAN_API_PORT` | `9090` | HTTP API port |
| `ZAMAN_API_KEY` | _(empty)_ | Require auth on API |
| `ZAMAN_HEP_PASSWORD` | _(empty)_ | HEP password check |
| `ZAMAN_HEP_ALLOW` | _(empty)_ | HEP peer IP allowlist |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP over TLS |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | SIP methods to echo |
| `ZAMAN_PROBE` | `0` | Enable active probe API |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete old captures |

Full list in the [spec](spec.md).

---

## Project layout

```
zaman/
  core/main.mko           # capture, HEP, echo, API, metrics, QoS (Mako)
  web/main.weft            # dashboard, auth, alerting, SLA (Weft/HTMX)
  install.sh               # one-command Linux installer
  Dockerfile               # multi-stage container build
  docker-compose.yml       # SQLite / Postgres / ClickHouse profiles
  deploy/                  # systemd units, bare-metal installer
  scripts/                 # smoke tests, demo, CLI, HEP/SIP test clients
  docs/DEPLOYMENT.md       # sizing, architecture, cloud setup
  spec.md                  # engineering spec (source of truth)
  SECURITY_REVIEW.md       # threat model and hardening status
```

## What's not done

- Password hashing uses SHA-256 (should be bcrypt/scrypt/Argon2id)
- Session secret is regenerated on restart (should be persisted)
- ClickHouse queries use string interpolation (should be parameterized)
- No public package in any package manager yet
- Not tested at carrier scale (millions of calls/day)

Full list in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).

## License

Apache-2.0
