# Zaman Security Review

**Scope:** `core-go/*.go` (v0.4.0), `web/main.go`, `web/static/`
**Date:** 2026-10-12
**Status:** All findings remediated.

---

## Architecture Security

| Layer | Protection |
|-------|-----------|
| API authentication | `X-API-Key` or `Authorization: Bearer` with constant-time comparison |
| Session auth | HMAC-SHA256 signed cookies, 24-hour expiry, HttpOnly + Secure + SameSite=Lax |
| Password storage | 25,000-round HMAC-SHA256 key stretching with per-user random salt |
| HEP authentication | Optional password with constant-time comparison |
| HEP peer control | IP allowlist (`ZAMAN_HEP_ALLOW`) |
| Rate limiting | Per-IP per-second bucket (default 100 req/s) |
| Login brute force | 5 attempts per 60 seconds per IP |
| Credential redaction | Authorization and Proxy-Authorization headers stripped before storage |
| Network isolation | UFW blocks ports 9090 and 3000 externally; nginx proxies to 3000 |
| Path traversal | Reject any URL path containing `..` |
| CSRF | SPA uses fetch (not form posts); session cookie is SameSite=Lax |
| SQL injection | Parameterized queries via `database/sql`; `sqlQuote()` for dynamic WHERE clauses |
| Probe safety | Blocks RFC1918, link-local (169.254.x), and cloud metadata endpoints |
| TLS | HEP/TLS with configurable cert/key; minimum TLS 1.2 |
| Session persistence | HMAC secret stored in `data/zaman-web-secret.key` (mode 0600), survives restarts |
| User file permissions | `data/zaman-users.json` stored mode 0600 |
| TCP buffer limits | HEP TCP/TLS connections capped at 2 MB per connection |

## Recommendations

- Use a reverse proxy (nginx) with a valid TLS certificate for production.
- Set `ZAMAN_API_KEY` on both core and web to require authentication.
- Rotate the API key periodically.
- Monitor `/api/anomalies` for auth failure spikes.
- Keep PostgreSQL on localhost with peer authentication.
- Back up `data/` directory (contains user accounts and session secrets).
