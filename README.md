# Zaman

**Integrated SIP monitoring + echo system** — capture, metrics, and live UI in one stack.

Homer, Prometheus, and Grafana solve pieces of VoIP observability, but they are separate systems. Zaman joins them:

| Role | Usual tool | In Zaman |
|------|------------|----------|
| SIP / HEP capture | Homer | **Mako core** (`core/`) |
| Metrics / scrape | Prometheus | **`/metrics` + JSON API** on core |
| Live dashboard | Grafana | **Weft + HTMX + Tailwind 4** (`web/`) |
| Reachability | ad-hoc scripts | **OPTIONS echo + active probe** |

Stack:

- **[Mako](https://mako-lang.com)** — SIP parse/build, UDP echo, HEPv3 ingest, ring store, Prometheus text
- **[Weft](https://github.com/loreste32/weft)** — HTMX dashboard and control plane
- **HTMX** — partials, live refresh, probe form
- **Tailwind CSS 4** — browser CDN (`@tailwindcss/browser`)

### Concurrency: Mako `crew` / `kick` (not Go)

Mako has **no free `go` keyword** and no goroutines. Concurrency is **colorless structured**:

| Piece | Role |
|-------|------|
| `crew` | Structured scope — jobs must be joined (or drained) before the crew ends |
| `kick` | Start a job: `db_writer`, SIP/UDP, HEP/UDP, HTTP, optional HEP/TCP & HEP/TLS |
| `join` | Wait for a kicked job’s result |
| `chan[string]` | Capture JSON from workers → **one** kicked `db_writer` (serialized SQLite) |
| `for j in range ch` | DB writer drains typed channel until close (Mako 0.4.17 codegen fix) |
| nested `crew` + `kick` | HEP/TCP: one job per accepted session (`drain(0)` detaches) |
| HEP/TLS | Inline session per accept (no kick): read → close TLS → then parse/enqueue |

**Not used:** `go f()`, goroutine pools, `async`/`await` (lex-rejected).

Producers never open SQLite — they only `ch.send(record_json)`. Metrics expose `db_ok` / `db_err`.

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
  crew.kick → db_writer (for j in range ch) ← sip / hep / http / tcp / tls
```

## Quick start

Requirements: **Mako ≥ 0.4.17** and `weft` on `PATH` (both typically under `~/.local/bin`).
Check with `make doctor` / `mako version`.

```bash
# build core
make build

# smoke test (high ports, no root)
make smoke

# full demo: core + dashboard
./scripts/demo.sh
# open http://127.0.0.1:3000
```

Manual two-process run:

```bash
# terminal 1 — core (SIP 15060, HEP 19060, API 19090)
./bin/zaman-core 15060 19060 19090

# terminal 2 — UI
ZAMAN_CORE=http://127.0.0.1:19090 weft run web/main.weft
```

Default production-ish ports when run with no args: **SIP 5060**, **HEP 9060**, **API 9090** (5060 may need privileges).

## Core API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Liveness |
| `GET /api/metrics` | JSON counters + method mix |
| `GET /metrics` | Prometheus text exposition |
| `GET /api/messages?limit=&call_id=&transport=` | Captures from **SQLite** (falls back to ring) |
| `GET /api/messages/:id` | One message by durable DB id |
| `GET /api/report` / `/api/report/summary` | Totals, methods, transports |
| `GET /api/report/daily?limit=` | Daily rollup counters |
| `GET /api/report/top-calls?limit=` | Busiest Call-IDs |
| `POST /api/probe` | `{"host","port","timeout_ms"}` → OPTIONS RTT |

### Database / reporting

Captures are written to **SQLite** (WAL) for durable history and reports.

| Env | Default | Meaning |
|-----|---------|---------|
| `ZAMAN_DB` | `data/zaman.db` | SQLite file path |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Drop older rows (0 = keep forever) |

Tables: `captures` (full message + `record_json`), `report_daily` (day/method/transport counts).

```bash
# after traffic
curl -s http://127.0.0.1:9090/api/report | jq .
curl -s 'http://127.0.0.1:9090/api/report/top-calls?limit=10'
sqlite3 data/zaman.db 'SELECT method, transport, COUNT(*) FROM captures GROUP BY 1,2;'
```

### Echo behaviour

Inbound UDP SIP is always captured. Auto-reply default is **OPTIONS → 200 OK** only.

- `REGISTER` → **401** (does not pretend to be a registrar)
- Other methods: only if listed in `ZAMAN_ECHO_METHODS` or `ZAMAN_ECHO_ALL=1`

### HEP (HEPv3 / EEP)

Native **HEPv3** collector — **UDP, TCP, and TLS** — compatible with Kamailio `sipcapture`, OpenSIPS HEP, heplify, captagent, and other Homer agents.

| Transport | Default | Env |
|-----------|---------|-----|
| UDP | `:9060` | `ZAMAN_HEP_PORT` |
| TCP (length-framed stream) | `:9062` | `ZAMAN_HEP_TCP=1` (opt-in), `ZAMAN_HEP_TCP_PORT` |
| TLS | `:9061` | `ZAMAN_HEP_TLS=1` + cert/key |

| Chunk | Type | Used for |
|-------|------|----------|
| IP family / proto | 1–2 | version, UDP/TCP |
| IPv4 / IPv6 | 3–6 | endpoints |
| ports / timestamps | 7–10 | src/dst, capture time |
| proto type | 11 | `1=SIP`, `5=RTCP`, … |
| node id / password / name | 12 / 14 / 19 | agent identity + optional auth |
| payload / correlation | 15 / 17 | packet + Call-ID fallback |

Records: `transport=HEP3|HEP3/TCP|HEP3/TLS`, `proto=sip|rtcp|…`, `src`/`dst`, `hep_node_*`.

```bash
# UDP
python3 scripts/send_hep.py --port 9060 --call-id test@lab

# TCP (multi-frame stream)
python3 scripts/send_hep.py --tcp --port 9060 --count 3

# TLS
ZAMAN_HEP_TLS=1 \
  ZAMAN_HEP_TLS_CERT=data/tls/hep.crt \
  ZAMAN_HEP_TLS_KEY=data/tls/hep.key \
  ./bin/zaman-core
python3 scripts/send_hep.py --tls --insecure --port 9061

# password + peer allowlist
ZAMAN_HEP_PASSWORD=s3cret ZAMAN_HEP_ALLOW=10.0.0.,203.0.113.5 ./bin/zaman-core
```

## Dashboard pages

- **Overview** — stats, method chart, live message table
- **Messages** — filter by Call-ID, detail + raw SIP
- **Call ladder** — per-Call-ID signaling timeline
- **Echo probe** — active OPTIONS RTT against any host
- **Metrics** — charts + Prometheus scrape snippet

## Security (read this)

**v0.1 has no authentication.** Treat as lab-only on trusted networks. Full adversarial review: [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).

Hardened defaults after review:

| Control | Default |
|---------|---------|
| Active probe (`POST /api/probe`) | **Off** (`ZAMAN_PROBE=1` to enable) |
| SIP echo methods | **OPTIONS only** (`ZAMAN_ECHO_METHODS`) |
| REGISTER | **401 Unauthorized** (never fake a successful register) |
| Probe timeout | Capped at **5s**; probe UDP socket closed |
| Auth headers in captures | **Redacted** before store/export |
| API auth | Still none — firewall / reverse-proxy required |

## Config

| Env / arg | Default | Meaning |
|-----------|---------|---------|
| `ZAMAN_SIP_HOST` | `0.0.0.0` | SIP/HEP bind host (prefer interface/firewall) |
| `ZAMAN_SIP_PORT` / argv1 | `5060` | SIP UDP |
| `ZAMAN_HEP_PORT` / argv2 | `9060` | HEP UDP |
| `ZAMAN_API_PORT` / argv3 | `9090` | HTTP API (**no auth**) |
| `ZAMAN_ECHO_ALL` | `0` | Echo every SIP request (lab only) |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | Comma list of methods to auto-reply |
| `ZAMAN_PROBE` | `0` | Enable `POST /api/probe` |
| `ZAMAN_PROBE_ALLOW_PRIVATE` | `0` | Allow probing RFC1918 (localhost always ok) |
| `ZAMAN_HEP_PASSWORD` | _(empty)_ | Require HEP node password chunk |
| `ZAMAN_HEP_ALLOW` | _(empty)_ | Comma IP/prefix allowlist for HEP peers |
| `ZAMAN_HEP_TCP` | `0` | Enable HEP over TCP (opt-in) |
| `ZAMAN_HEP_TCP_PORT` | `9062` | TCP listen port (`0` = same as UDP HEP port) |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP over TLS |
| `ZAMAN_HEP_TLS_PORT` | `9061` | TLS listen port |
| `ZAMAN_HEP_TLS_CERT` / `KEY` | | PEM paths for TLS |
| `ZAMAN_API_KEY` | _(empty)_ | Require `X-API-Key` / Bearer on API (except `/health`) |
| `ZAMAN_CORE` (web) | `http://127.0.0.1:9090` | Core base URL |
| `ZAMAN_API_KEY` (web) | | Same key so dashboard can call core |

## Project layout

```
zaman/
  core/main.mko      # Mako SIP/HEP/metrics/API
  web/main.weft      # Weft HTMX dashboard
  scripts/smoke.sh
  scripts/demo.sh
  Makefile
```

## Roadmap (honest)

This is a focused v0.1:

- [x] SIP UDP capture + OPTIONS-class echo
- [x] HEPv3 payload ingest (UDP / TCP / TLS)
- [x] In-memory ring (512) + JSON API
- [x] **SQLite persistence + reporting APIs**
- [x] Prometheus `/metrics`
- [x] Active OPTIONS probe with RTT
- [x] HTMX + Tailwind 4 dashboard (+ Reports page)
- [ ] Full SIP ladder SDP/media correlation
- [ ] Auth on dashboard / API (API key optional on core)
- [ ] Multi-node fan-in

## License

Apache-2.0 (aligned with Weft / typical Mako apps).
