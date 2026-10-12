# Zaman Product and Engineering Spec

**Status:** v0.4 production
**Stack:** Go core (`core-go/`) and Go web proxy (`web/`) with SPA dashboard
**Verified on:** Go >= 1.22, PostgreSQL >= 14
**License:** Apache-2.0

This document is the source of truth. When behavior is ambiguous, this spec
wins over README text.

---

## 1. Product Scope

Zaman is an integrated SIP/HEP monitoring system for VoIP operations teams. It
captures SIP signaling, receives HEP3 telemetry, stores searchable history, and
provides realtime dashboards for troubleshooting calls, carriers, nodes, reports,
SLA, and alerts.

### Goals

1. Capture native SIP over UDP and HEPv3 over UDP, TCP, and TLS.
2. Echo monitoring pings safely, with OPTIONS returning 200 by default.
3. Store captures in PostgreSQL with batch writes and automatic retention.
4. Provide realtime CPS, concurrent calls, active calls, ASR, ACD, NER, message
   rate, failure rate, live feed, and node health.
5. Group messages by Call-ID and expose all messages for the selected Call-ID.
6. Provide an interactive SIP ladder with SVG arrows, hover highlighting,
   click-to-view raw SIP, PCAP export, and live refresh for active calls.
7. Search by Call-ID, IP address, from number, to number, method, transport,
   agent, status, time range, and regex.
8. Carrier analysis with per-destination ASR/ACD breakdown and trend charts.
9. GeoIP lookup with map display for any endpoint IP.
10. Phone number search with per-number ASR/ACD/call history.
11. SLA gauges with configurable targets and per-IP breakdown.
12. Webhook alerts for anomaly conditions.
13. RBAC with admin, operator, and viewer roles.
14. Full-screen wallboard mode for NOC displays.

### Non-Goals

- Full media recording or RTP reconstruction.
- Multi-tenant data isolation (future consideration).
- AI-based anomaly detection (future consideration).
