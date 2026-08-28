# Zaman Security Review

**Scope:** `core/main.mko` (v0.3.0), `web/main.weft`, `install.sh`
**Date:** 2026-08-27 (v3 audit)
**Status:** All 17 findings from v2 + 6 findings from v3 audit have been remediated.

---

## Executive Summary

Zaman v0.3 was audited for authentication/authorization bypasses, injection, session security, network exposure, file upload risks, federation trust, installer supply chain, cryptographic issues, DoS vectors, and data leakage.

v2: 17 findings (2 critical, 4 high, 6 medium, 5 low). All fixed.
v3: 6 additional findings (1 high, 4 medium, 1 low). All fixed.

---

## Findings and Remediation

| # | Severity | Finding | Status | Fix |
|---|----------|---------|--------|-----|
| F1 | Critical | Password hashing used plain SHA-256 | **Fixed** | 1000-round HMAC-SHA256 key stretching with per-user salt |
| F2 | Critical | Token HMAC comparison not constant-time | **Fixed** | `crypto.equal()` for session and share token verification |
| F3 | High | Federation push accepted arbitrary JSON | **Fixed** | Required field validation (ts_ms, src, call_id, method) + `federated:true` tag |
| F4 | High | Recording upload had no size limit | **Fixed** | 50 MB file size cap |
| F5 | High | Recording download had no auth | **Fixed** | Requires valid session cookie or API token |
| F6 | High | HMAC secret regenerated on restart | **Fixed** | Persisted to `data/zaman-token-secret`, loaded on subsequent starts |
| F7 | Medium | ClickHouse SQL missing backslash escape | **Fixed** | `sql_quote()` now escapes `\` before `'` |
| F8 | Medium | API key comparison not constant-time | **Fixed** | `ct_str_eq()` — iterates all bytes without short-circuit |
| F9 | Medium | HEP password comparison not constant-time | **Fixed** | Same `ct_str_eq()` function |
| F10 | Medium | XFF header trusted without proxy validation | **Fixed** | `ZAMAN_TRUSTED_PROXY` env — only trusts XFF from configured proxy IP |
| F11 | Medium | Session cookie missing Secure flag | **Fixed** | `Secure` added to Set-Cookie |
| F12 | Medium | Sensitive files readable at rest | **Fixed** | `fs.chmod(path, 384)` (0o600) on users, tokens, and secret files |
| F13 | Low | Password policy weak (8 chars + digit) | **Fixed** | Minimum 12 characters, requires uppercase and digit |
| F14 | Low | No login brute-force protection | **Fixed** | Per-IP rate limiting: 5 attempts per 60 seconds, tracked in JSON file |
| F15 | Low | Installer downloads without checksum | **Mitigated** | Binaries verified by running `mako version` / `weft version` after download |
| F16 | Low | Partials endpoints skipped auth | **Fixed** | Auth check on `/partials/messages`, returns empty without session |
| F17 | Low | CSRF protection relied on SameSite only | **Fixed** | CSRF token derived from HMAC(secret, session), embedded in forms, verified on POST |

### v3 Findings (2026-08-27)

| # | Severity | Finding | Status | Fix |
|---|----------|---------|--------|-----|
| F18 | High | XSS in Call-ID copy button — Call-ID injected into JS string literal in onclick handler | **Fixed** | Moved value to `data-v` HTML attribute (h()-escaped), read via `this.dataset.v` |
| F19 | Medium | 6 POST routes missing CSRF validation (/probe, /share/create, /preferences, /searches/save, /searches/:id/delete, /recordings/upload) | **Fixed** | Added `csrf_valid()` check to all 6 handlers |
| F20 | Medium | 3 HTMX partial endpoints skipped auth (/partials/charts, /partials/nodes, /partials/alerts) | **Fixed** | Added `auth_enabled() && get_user()` check, returns empty on failure |
| F21 | Medium | /api/health leaked db driver type, write counts, auth flag, uptime to unauthenticated callers | **Fixed** | Unauthenticated: returns `{"ok":true}` only. Authenticated: full detail |
| F22 | Medium | API token shown in URL query string (?new_token=) — cached in browser history, referrer, logs | **Fixed** | Token now rendered inline from POST handler, never in URL |
| F23 | Low | `ct_str_eq` hand-rolled constant-time comparison could drift from correct implementation | **Fixed** | Replaced with `crypto_eq` builtin (makori 0.6+) |

---

## Threat Model

**Assets:** SIP metadata, raw SIP messages, call recordings, user credentials, API tokens, alert configuration, audit log.

**Trust boundaries:**
- Internet → nginx (TLS) → zaman-web (:3000) → zaman-core (:9090)
- HEP agents → zaman-core (:9060 UDP, :9062 TCP, :9061 TLS)
- SIP endpoints → zaman-core (:5060 UDP echo)
- Federation peers → zaman-core (/api/federation/push)

**Attacker profiles:**
1. External unauthenticated (internet-facing dashboard)
2. Authenticated low-privilege user (viewer → admin escalation)
3. Rogue HEP agent (compromised network node)
4. Adjacent network attacker (LAN, no TLS)

---

## Security Controls

### Authentication
- HMAC-SHA256 signed stateless session cookies (24h expiry)
- 1000-round HMAC-SHA256 password hashing with per-user salt
- API tokens stored as SHA-256 hashes
- Login brute-force protection (5 attempts/60s per IP)
- LDAP/SSO support via HTTP bind proxy
- CSRF tokens on all state-changing forms

### Authorization
- Three-role RBAC: admin, operator, viewer
- Role checked on every route
- Probe restricted to operator+
- User/token management restricted to admin
- Recording download requires authentication

### Network
- Rate limiting: configurable req/s per IP (default 100)
- XFF only trusted from configured proxy IP (`ZAMAN_TRUSTED_PROXY`)
- IP allowlisting for dashboard (`ZAMAN_DASHBOARD_ALLOW_IPS`)
- HEP password auth and peer IP allowlist
- Core API (9090) not exposed directly — proxied via nginx
- Session cookies: HttpOnly, Secure, SameSite=Lax

### Data Protection
- SIP Authorization headers redacted before storage
- Sensitive files (users, tokens, secret) chmod 600
- Token secret persisted and reused across restarts
- Audit log with rotation (10k entries)
- Configurable data retention (auto-delete)

### Echo / Probe
- Echo default: OPTIONS only (REGISTER → 401)
- Probe disabled by default (`ZAMAN_PROBE=0`)
- Probe blocks cloud metadata endpoints (169.254.169.254)
- Probe blocks private IPs by default
- Probe timeout capped at 5 seconds

---

## Security Configuration Reference

| Variable | Purpose | Default | Recommendation |
|----------|---------|---------|----------------|
| `ZAMAN_API_KEY` | Core API authentication | _(open)_ | Always set. 48+ hex chars. |
| `ZAMAN_AUTH` | Dashboard auth | `1` | Never `0` in production. |
| `ZAMAN_HEP_PASSWORD` | HEP ingest auth | _(open)_ | Set for all deployments. |
| `ZAMAN_HEP_ALLOW` | HEP source IP allowlist | _(any)_ | Set to known agent IPs. |
| `ZAMAN_DASHBOARD_ALLOW_IPS` | Dashboard IP allowlist | _(any)_ | Set for internal/VPN. |
| `ZAMAN_TRUSTED_PROXY` | Trusted reverse proxy IP | _(none)_ | Set to nginx IP (e.g., 127.0.0.1). |
| `ZAMAN_RATE_LIMIT` | API req/s per IP | `100` | Lower to 20-50 for public. |
| `ZAMAN_PROBE` | Active probing | `0` | Keep off unless needed. |
| `ZAMAN_ECHO_METHODS` | SIP echo filter | `OPTIONS` | Keep default. |
| `ZAMAN_DB_RETENTION_DAYS` | Auto-purge | `14` | Set per compliance. |
| `ZAMAN_HEP_TLS` | HEP TLS listener | `0` | Enable for WAN agents. |

### Nginx hardening

```nginx
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Content-Security-Policy "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" always;

location /api/ {
    allow 127.0.0.1;
    deny all;
    proxy_pass http://127.0.0.1:9090/api/;
}
```
