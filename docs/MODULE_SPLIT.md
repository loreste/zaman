# Zaman Module Split

The core was split into focused modules using Makori `pull` imports. Makori
0.6.32 adds `crew(fail_fast=true)` structured concurrency, zero-allocation
small channels, and position-aware move semantics — all used in the current
layout.

## Core Layout

- `core/main.mko`
  - Process startup, ports, single `crew(fail_fast=true)` worker orchestration.
- `core/config.mko`
  - Env parsing, feature flags, API key handling, retention settings.
- `core/sip.mko`
  - SIP parsing, header extraction, redaction, call state helpers.
- `core/hep.mko`
  - HEP3 decode, peer allow rules, UDP/TCP/TLS workers.
- `core/db.mko`
  - DB open/init, SQLite/PostgreSQL/ClickHouse helpers, writer loop,
    batched retention (LIMIT 500 per backend).
- `core/reports.mko`
  - Report, KPI, SLA, realtime, active-call queries.
- `core/http_api.mko`
  - HTTP routing and JSON response assembly.
- `core/probe.mko`
  - OPTIONS probe safety checks and probe execution.

## Target Web Layout

Weft currently runs from one entry file. Split by extracting pure rendering and
client helpers first, while keeping `web/main.weft` as the entry point.

- `web/main.weft`
  - App startup, middleware, route registration.
- `web/auth.weft`
  - RBAC, sessions, login, users, API tokens, audit log.
- `web/core_client.weft`
  - Typed wrappers around core API calls.
- `web/components.weft`
  - Layout, nav, cards, badges, tables, shared controls.
- `web/pages/overview.weft`
- `web/pages/messages.weft`
- `web/pages/calls.weft`
- `web/pages/ladder.weft`
- `web/pages/reports.weft`
- `web/pages/metrics.weft`
- `web/pages/sla.weft`
- `web/pages/admin.weft`

Until Weft has the same mature package workflow as Makori, keep the web split as
pure helper extraction only and verify with `weft check web/main.weft`.

## Refactor Order

1. Extract core pure helpers: JSON escaping, env parsing, endpoint parsing,
   redaction, protocol name helpers.
2. Extract core config/probe safety. This is low risk and easy to test.
3. Extract core DB init/query helpers after PostgreSQL report latency is stable.
4. Extract report/SLA/realtime query functions together so KPI math stays
   coherent.
5. Extract HEP/SIP parsing last; these are hot-path and live-call sensitive.
6. Split web components, then pages. Keep routes unchanged until all links and
   HTMX partials are verified.

## Guardrails

- No hardcoded deployment hosts, private IPs, credentials, keys, or `.pem`
  references in source.
- Do not add startup-time heavyweight DDL for production tables. Use separate
  migration or maintenance scripts for large indexes.
- Each extraction must pass:
  - `makori check core/main.mko`
  - `makori build --release core/main.mko -o bin/zaman-core`
  - `weft check web/main.weft`
  - `./scripts/test_integration.sh` unless the failure is a known unrelated
    contract mismatch documented in the change.
- Deploy server-built Linux binaries only. Do not upload local macOS binaries to
  Linux servers.
