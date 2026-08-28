# Zaman Product and Engineering Spec

**Status:** v0.3 production-track
**Stack:** Makori core (`core/main.mko`) and Weft dashboard (`web/main.weft`)
**Verified on:** Makori >= 0.6.1, Weft >= 0.6.0
**License:** Apache-2.0

This document is the source of truth. When behavior is ambiguous, this spec
wins over README text.

---

## 1. Product Scope

Zaman is an integrated SIP/HEP monitoring system for VoIP operations teams. It
captures SIP signaling, receives HEP3 telemetry, stores searchable history, and
provides realtime dashboards for troubleshooting calls, peers, nodes, reports,
SLA, and alerts.

### Goals

1. Capture native SIP over UDP and HEPv3 over UDP, TCP, and TLS.
2. Echo monitoring pings safely, with OPTIONS returning 200 by default.
3. Store captures in SQLite, PostgreSQL, or ClickHouse.
4. Provide realtime CPS, concurrent calls, active calls, ASR, NER, message rate,
   failure rate, live feed, and node health.
5. Group messages by Call-ID and expose all messages for the selected Call-ID.
6. Provide a dedicated `/ladder?call_id=...` page for SIP ladder analysis.
7. Search by Call-ID, IP address, from number, to number, method, transport,
   agent, status, and timestamp/date range.
8. Support source/destination IP history and runtime labels for peers, sites,
   carriers, customers, and SIP nodes.
9. Provide report building and export across telecom KPIs and filtered message
   or call datasets.
10. Track SLA by agent, destination, availability, ASR, failures, and CPS.
11. Support RBAC, API tokens, audit logs, optional LDAP bind proxy, and optional
    dashboard IP allowlisting.
12. Support Slack, webhook, and email alert channels.
13. Keep deployment-specific hosts, credentials, and labels outside source.

### Non-Goals

- Zaman is not a SIP proxy and must not be placed in the live call path.
- Zaman is not a complete RTP media recorder. SIP PCAP export is supported;
  audio playback depends on uploaded or captured media artifacts.
- Zaman is not a client-side SPA. The dashboard is server-rendered Weft with
  HTMX for live partial refreshes.

---

## 2. Runtime Components

### zaman-core

Makori service responsible for SIP capture, HEP ingest, SIP parsing/redaction,
database writes, schema migration, JSON APIs, Prometheus metrics, realtime
windows, reports, exports, SLA, QoS, anomaly detection, probes, and federation.

| Service | Default |
|---------|---------|
| SIP UDP | 5060 |
| HEP UDP | 9060 |
| API HTTP | 9090 |
| HEP TLS | 9061 |
| HEP TCP | 9062 |

### zaman-web

Weft dashboard responsible for login, RBAC, overview, NOC, messages, calls,
ladder, IP history, metrics, reports, SLA, alerts, users, tokens, audit pages,
HTMX realtime partials, and runtime labels.

Default port: 3000 behind nginx.

---

## 3. Database Backends

| Backend | Use Case | Notes |
|---------|----------|-------|
| SQLite | lab, demo, very small deployments | zero-config, local file |
| PostgreSQL | production deployments | persistent history and better concurrency |
| ClickHouse | very high volume or long retention | append-heavy analytics |

Primary capture fields:

| Field | Meaning |
|-------|---------|
| `id` | message identifier |
| `ts_ms` | epoch timestamp in milliseconds |
| `src`, `dst` | source and destination endpoint |
| `transport` | SIP/HEP transport |
| `proto` | protocol family such as `sip` or `rtcp` |
| `agent` | HEP node/agent name |
| `kind` | `request` or `response` |
| `method` | SIP method or parsed response method |
| `status` | SIP response code |
| `call_id` | SIP Call-ID |
| `from_h`, `to_h`, `cseq`, `ruri` | SIP header fields |
| `hep_node_id`, `hep_node`, `hep_cid` | HEP metadata |
| `raw_b64` | redacted raw SIP payload |
| `record_json` | structured capture JSON |

Retention is controlled by `ZAMAN_DB_RETENTION_DAYS`.

---

## 4. Dashboard Pages

| Route | Page | Role | Features |
|-------|------|------|----------|
| `/` | Overview | all | Realtime CPS, concurrent calls, active calls, message rate, failures, ASR, node health, charts, live feed, notifications |
| `/noc` | NOC | all | Node health, server naming, stale/degraded detection |
| `/messages` | Messages | all | Call-ID grouping, filters, saved searches, JSON/CSV/PCAP export |
| `/messages/:id` | Message Detail | all | Full decoded SIP, headers, source/destination, ladder drilldown |
| `/ladder` | SIP Ladder | all | Dedicated Call-ID ladder with chronological rows, directional flow, PCAP, media, related legs |
| `/calls` | Calls | all | Realtime call operations, active calls, CPS, concurrent calls, recent dialogs, source/destination IPs |
| `/ip` | IP History | all | Source/destination history, labels, paths, peers, timeout drilldowns |
| `/probe` | Echo Probe | operator+ | Active OPTIONS RTT test |
| `/metrics` | Metrics | all | Operational breakdowns, source/destination IPs, response codes, Prometheus guidance |
| `/report` | Reports | all | Report builder, telecom KPIs, ASR/NER, top talkers, routes, daily rollup, export |
| `/sla` | SLA | all | Availability, ASR, failures, CPS, destination targets |
| `/alerts` | Alerts | operator+ | Alert rules, notification channels, alert history |
| `/admin/users` | Users | admin | Create/delete users, assign roles, reset passwords |
| `/admin/tokens` | API Tokens | admin | Generate/revoke automation tokens |
| `/admin/audit` | Audit Log | admin | Login attempts, admin actions, exports |

---

## 5. SIP Ladder Behavior

Ladder links must point to `/ladder?call_id=<value>`, not `/calls`.

The ladder page must:

- Fetch all capture rows for the exact Call-ID.
- Preserve literal Call-ID characters required by the core API.
- Include SIP requests and SIP responses.
- Normalize response rows from CSeq when needed, so responses render as
  `100 INVITE`, `180 INVITE`, `200 PRACK`, `200 BYE`, and similar labels.
- Show a chronological table with message id, label, source, destination, CSeq,
  and seen time.
- Show the directional ladder visualization.
- Link each row to `/messages/:id`.
- Expose PCAP export and available media/recording actions.

---

## 6. Realtime Metrics

Realtime values are based on recent windows, not all-time counters.

| Metric | Meaning |
|--------|---------|
| CPS | distinct INVITE Call-IDs per second in the selected window |
| Concurrent calls | Call-IDs with INVITE activity and no later BYE/CANCEL/final failure in the live window |
| Active calls | currently open dialogs observed in the live sample |
| Message rate | total captured messages per second |
| Attempts | distinct INVITE Call-IDs |
| Failures | 4xx/5xx responses |
| ASR | answered calls divided by attempts |
| NER | network effectiveness from successful/non-user-failure outcomes |

OPTIONS keepalives must be separated from calls in call reports and active-call
views.

---

## 7. Core API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | open | Liveness and version |
| GET | `/api/metrics` | key? | JSON counters |
| GET | `/metrics` | key? | Prometheus text |
| GET | `/api/messages` | key? | Message search: `limit`, `call_id`, `agent`, `method`, `transport`, `ip`, `from_number`, `to_number`, `status`, `since_ms`, `until_ms` |
| GET | `/api/messages/:id` | key? | Single message |
| GET | `/api/report/summary` | key? | Totals, methods, transports |
| GET | `/api/report/kpi` | key? | ASR, NER, registration stats |
| GET | `/api/report/response-codes` | key? | Status distribution |
| GET | `/api/report/top-calls` | key? | Busiest Call-IDs |
| GET | `/api/report/top-talkers` | key? | Busiest endpoints |
| GET | `/api/report/agents` | key? | HEP node inventory |
| GET | `/api/report/daily` | key? | Daily rollup |
| GET | `/api/report/cps` | key? | Calls per minute |
| GET | `/api/realtime` | key? | Windowed live stats: `window` in minutes |
| GET | `/api/nodes` | key? | Per-agent health |
| GET | `/api/anomalies` | key? | Active anomaly indicators |
| GET | `/api/export` | key? | JSON/CSV/PCAP export using message filters |
| GET | `/api/related` | key? | Related Call-IDs |
| POST | `/api/probe` | key? | OPTIONS RTT test |
| POST | `/api/federation/push` | key? | Remote instance capture push |

---

## 8. Configuration

| Env | Default | Purpose |
|-----|---------|---------|
| `ZAMAN_DB_DRIVER` | `sqlite` | `sqlite`, `postgres`, or `clickhouse` |
| `ZAMAN_DB` | `data/zaman.db` | SQLite path |
| `ZAMAN_DB_DSN` | backend-specific | PostgreSQL connection string |
| `ZAMAN_CH_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `ZAMAN_CH_DB` | `zaman` | ClickHouse database name |
| `ZAMAN_DB_RETENTION_DAYS` | `14` | Auto-delete older captures, `0` keeps all |
| `ZAMAN_SIP_HOST` | `0.0.0.0` | Bind address |
| `ZAMAN_SIP_PORT` | `5060` | SIP UDP |
| `ZAMAN_HEP_PORT` | `9060` | HEP UDP |
| `ZAMAN_API_PORT` | `9090` | HTTP API |
| `ZAMAN_API_KEY` | empty | Require key on API except `/health` |
| `ZAMAN_ECHO_METHODS` | `OPTIONS` | SIP methods that get auto-reply |
| `ZAMAN_ECHO_ALL` | `0` | Echo every request, lab only |
| `ZAMAN_PROBE` | `0` | Enable probe API |
| `ZAMAN_PROBE_ALLOW_PRIVATE` | `0` | Allow probing RFC1918 targets |
| `ZAMAN_HEP_TCP` | `0` | Enable HEP/TCP |
| `ZAMAN_HEP_TCP_PORT` | `9062` | HEP/TCP port |
| `ZAMAN_HEP_TLS` | `0` | Enable HEP/TLS |
| `ZAMAN_HEP_TLS_PORT` | `9061` | HEP/TLS port |
| `ZAMAN_HEP_TLS_CERT` | empty | HEP/TLS certificate path |
| `ZAMAN_HEP_TLS_KEY` | empty | HEP/TLS key path |
| `ZAMAN_HEP_PASSWORD` | empty | Optional HEP auth |
| `ZAMAN_HEP_ALLOW` | empty | Optional HEP peer allowlist |
| `ZAMAN_AUTH` | enabled | Set `0` to disable dashboard auth |
| `ZAMAN_DASHBOARD_ALLOW_IPS` | empty | Optional dashboard IP allowlist |
| `ZAMAN_CORE` | `http://127.0.0.1:9090` | Core URL for dashboard |
| `ZAMAN_BRAND_NAME` | `Zaman` | Dashboard title |

Deployment-specific values must stay in runtime configuration, not source.

---

## 9. Runtime Data Files

Runtime state lives in `data/` or the configured data directory and must not be
committed.

| File | Purpose |
|------|---------|
| `zaman.db` | SQLite database when using the sqlite backend |
| `zaman-users.json` | User accounts with username, password hash, role, algorithm, and rounds |
| `zaman-api-tokens.json` | API token hashes and labels |
| `zaman-alerts.json` | Alert rules and notification channels |
| `zaman-alert-history.json` | Fired alert history |
| `zaman-searches.json` | Saved search profiles |
| `zaman-node-names.json` | Runtime node display names |
| `zaman-site-labels.json` | Runtime IP/site labels |
| `zaman-audit.jsonl` | Append-only audit log |
| `recordings/` | Call recordings named by Call-ID |
| `tls/` | HEP TLS certificates |

---

## 10. Security Model

- Dashboard users are admin, operator, or viewer.
- Operators can run probes and manage alerts.
- Admins manage users, tokens, and audit views.
- Local passwords use versioned 25k-round HMAC-SHA256 key stretching with
  per-user salt and constant-time verification.
- Legacy password hashes are upgraded after successful login.
- The session signing secret is persisted and chmod 600.
- API tokens are stored as hashes and shown once.
- SIP auth headers are redacted before storage.
- Optional dashboard IP allowlisting checks proxy-aware client addresses.
- Production API deployments should set `ZAMAN_API_KEY`.
- HEP deployments should restrict senders with firewall rules, allowlists, or
  HEP/TLS.
- ClickHouse string filters are SQL-quoted/escaped and numeric filters are
  parsed before query construction.

---

## 11. Build and Test

```bash
make doctor
make build
make check
make smoke
make demo
```

Direct checks:

```bash
makori check core/main.mko
weft check web/main.weft
```
