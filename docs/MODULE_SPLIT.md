# Zaman Module Layout

The system consists of two Go binaries and a client-side SPA.

## Core (`core-go/`)

| File | Purpose |
|------|---------|
| `main.go` | Entry point, config loading, worker orchestration (goroutines) |
| `sip.go` | SIP message parsing, header extraction, credential redaction, SDP extraction, echo replies |
| `hep.go` | HEP3 binary protocol decoder, UDP/TCP/TLS listeners, peer auth and allowlisting |
| `db.go` | PostgreSQL schema creation, batch inserts (100/tx), call_state upsert, partition management, retention |
| `api.go` | 39-endpoint HTTP API, auth middleware, rate limiting, static file serving |
| `cache.go` | 3-second cache refresh worker (realtime, nodes, calls, agents, SLA) |
| `reports.go` | SQL query builders for realtime, KPIs, agents, top talkers, CPS, trends, SLA, anomalies |
| `probe.go` | SIP OPTIONS synthetic probe with RTT measurement |
| `qos.go` | RTCP SR/RR parsing, MOS calculation (ITU-T G.107), RTP codec detection |
| `alerts.go` | Background webhook alert worker (60-second check interval) |

## Web (`web/`)

| File | Purpose |
|------|---------|
| `main.go` | Reverse proxy to core, cookie-based HMAC auth, user CRUD, node naming, saved searches, per-user prefs |

## SPA (`web/static/`)

| File | Purpose |
|------|---------|
| `index.html` | Shell HTML, CSS design system (semantic colors, type scale, theme tokens) |
| `app.js` | 17-page SPA with client-side hash routing, Chart.js, Leaflet maps, PCAP builder |

## Worker Model

The core runs as goroutines coordinated via context cancellation:

```
main()
  ├── dbWriter()        — channel consumer, batch inserts, partition/retention management
  ├── cacheWorker()     — 3-second refresh of expensive queries
  ├── sipWorker()       — UDP listener on SIP port
  ├── hepUDPWorker()    — UDP listener on HEP port
  ├── hepTCPWorker()    — TCP accept loop (optional)
  ├── hepTLSWorker()    — TLS accept loop (optional)
  ├── apiWorker()       — HTTP server
  └── alertWorker()     — webhook alert checker
```

All workers shut down gracefully on SIGINT/SIGTERM via context cancellation.
