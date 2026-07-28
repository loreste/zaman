# Zaman Security Review v2

**Scope:** `core/main.mko` (v0.2.0), `web/main.weft`, `install.sh`  
**Date:** 2026-07-27  
**Reviewer:** White-hat audit, code-level review  
**Status:** v0.2 adds RBAC, HMAC sessions, rate limiting, HEP password/IP allowlist, probe restrictions. Several issues remain.

---

## Executive Summary

Zaman v0.2 substantially improved over v0.1 (which had no auth at all). The dashboard now has RBAC with HMAC-SHA256 signed cookies, API key auth on the core, rate limiting, HEP password auth, IP allowlists, and probe SSRF protections. Good fundamentals.

Remaining risks ranked by severity:

| # | Severity | Issue |
|---|----------|-------|
| F1 | **Critical** | Password hashing uses unsalted SHA-256 (not a KDF) |
| F2 | **Critical** | Session/share token HMAC comparison is not constant-time |
| F3 | **High** | Federation push accepts arbitrary JSON into DB with no validation |
| F4 | **High** | Recording upload has no file type/size validation |
| F5 | **High** | Recording download endpoint has no auth check |
| F6 | **High** | HMAC secret regenerated on restart invalidates all sessions |
| F7 | **Medium** | ClickHouse queries use string interpolation (no parameterized queries) |
| F8 | **Medium** | Core API key compared with string equality (not constant-time) |
| F9 | **Medium** | HEP password compared with string equality (not constant-time) |
| F10 | **Medium** | XFF header trusted without validation for rate limiting |
| F11 | **Medium** | Session cookie missing `Secure` flag |
| F12 | **Medium** | User/token JSON files readable by process user (no encryption at rest) |
| F13 | **Low** | Password policy is weak (8 chars + 1 digit) |
| F14 | **Low** | No login brute-force rate limiting |
| F15 | **Low** | Installer downloads binaries over HTTPS but no checksum verification |
| F16 | **Low** | Partials endpoints skip auth check |
| F17 | **Low** | CSRF protection relies solely on SameSite=Lax |

---

## Threat Model

**Assets:** SIP metadata (Call-IDs, From/To URIs, IPs), raw SIP messages (may contain auth headers pre-redaction), call recordings, user credentials, API tokens.

**Trust boundaries:**
- Internet -> nginx (TLS termination) -> zaman-web (:3000) -> zaman-core (:9090)
- HEP agents (remote offices) -> zaman-core (:9060 UDP, :9062 TCP, :9061 TLS)
- SIP endpoints -> zaman-core (:5060 UDP echo)
- Federation peers -> zaman-core (/api/federation/push)

**Attackers:**
1. External unauthenticated (internet-facing)
2. Authenticated low-privilege user (viewer escalating to admin)
3. Rogue HEP agent (compromised network node)
4. Adjacent network attacker (LAN, no TLS)

---

## Findings

### F1: Critical — Password Hashing Uses SHA-256 (Not a KDF)

**File:** `web/main.weft` line 39  
**Code:** `crypto.sha256(salt + ":" + password)`

SHA-256, even with a salt, is not a password hashing function. It runs in nanoseconds on GPUs. A stolen `data/zaman-users.json` file (see F12) allows offline brute-force at billions of guesses/second.

**Fix:** Use bcrypt, scrypt, or Argon2id. If Weft doesn't support these natively, use PBKDF2-SHA256 with >= 600,000 iterations. The salt is already generated correctly (32 hex chars).

---

### F2: Critical — Token HMAC Comparison Is Not Constant-Time

**File:** `web/main.weft` lines 142, 1401  
**Code:** `if got_sig != expected { return null }`

Both `verify_token()` and `verify_share_token()` compare HMAC signatures using string equality (`!=`), which may short-circuit on the first differing byte. This enables timing attacks to forge session tokens byte-by-byte.

**Fix:** Use `crypto.constant_time_compare(got_sig, expected)` or equivalent. If unavailable, double-HMAC: `hmac(key, got_sig) == hmac(key, expected)` -- this makes timing differences uninformative.

---

### F3: High — Federation Push Accepts Arbitrary JSON

**File:** `core/main.mko` lines 2909-2957  
**Code:** The `/api/federation/push` endpoint parses JSON bodies and directly enqueues them into the DB via `db_enqueue()` and `cap_push()`.

Any authenticated API client can inject arbitrary records. The records are stored verbatim and rendered in the dashboard. While the dashboard uses `h()` for HTML escaping, the `record_json` field is stored raw and re-parsed -- a malformed record could corrupt queries or inject misleading call data.

No validation is performed on required fields (ts_ms, src, dst, method, etc.). No federation peer authentication exists beyond the shared API key.

**Fix:**
1. Validate required fields and types before enqueue.
2. Add a dedicated federation API key or mutual TLS for peer auth.
3. Tag federated records with a `source` field so they can be distinguished from local captures.

---

### F4: High — Recording Upload Has No File Validation

**File:** `web/main.weft` lines 2796-2810  
**Code:** `fs.write_bytes(path, f["body"])`

The upload accepts any file content and writes it directly to disk. No checks for:
- File size (DoS via disk exhaustion)
- File type (MIME type / magic bytes)
- Filename (the call_id is sanitized, but the content is not)

An operator-role user can upload multi-GB files or non-audio content.

**Fix:** Add a max file size check (e.g., 50MB). Validate audio magic bytes (RIFF header for WAV). The `sanitize_cid()` function correctly prevents path traversal.

---

### F5: High — Recording Download Has No Auth

**File:** `web/main.weft` lines 2787-2794  
**Code:** `app.get("/recordings/:cid", fn(req) { ... })` -- no `get_user()` call.

Anyone who can guess or enumerate a Call-ID can download call recordings without authentication. Call-IDs are visible in share links, URLs, and are often predictable.

**Fix:** Add `get_user(req, token_secret)` check. At minimum require viewer role.

---

### F6: High — Session Secret Regenerated on Restart

**File:** `web/main.weft` line 1841  
**Code:** `token_secret := secrets.token_hex(32)`

The HMAC signing key is generated at process start. Every restart invalidates all sessions and share links. This is acceptable for development but problematic in production:
- Rolling restarts force all users to re-login.
- Share links become invalid unexpectedly.
- No key rotation strategy exists.

**Fix:** Persist the secret to `data/zaman-token-secret` on first run. Load it on subsequent starts. Provide a rotation mechanism that accepts both old and new keys during a grace period.

---

### F7: Medium — ClickHouse String Interpolation

**File:** `core/main.mko` lines 344-352, 556-565  
**Code:** `http_post(url, sql)` where SQL is built via string concatenation.

While `sql_quote()` (line 359) escapes single quotes for SQLite/Postgres, the ClickHouse path sends raw SQL over HTTP. The `sql_quote()` function only replaces `'` with `''`, which is insufficient for ClickHouse's syntax (which also needs `\` escaping in some modes).

SIP header values are attacker-controlled. A crafted Call-ID like `x'); DROP TABLE captures; --` would be quoted to `'x''); DROP TABLE captures; --'` which is safe for standard SQL but depends on ClickHouse's parsing mode.

**Fix:** Use ClickHouse parameterized queries (`{param:String}` syntax) or validate that the ClickHouse server is configured in non-backslash-escape mode. Add `\` escaping to `sql_quote()`.

---

### F8: Medium — API Key Comparison Not Constant-Time

**File:** `core/main.mko` lines 181-198  
**Code:** `if str_eq(h, want)` and `if str_eq(tok, want)`

The API key comparison uses `str_eq` which likely short-circuits. Combined with the rate limiter, this is hard to exploit in practice, but it's a defense-in-depth gap.

**Fix:** Use constant-time comparison for the API key check.

---

### F9: Medium — HEP Password Not Constant-Time

**File:** `core/main.mko` lines 1982-1991  
**Code:** `if str_eq(info.node_pw, want)`

Same issue as F8 but for the HEP password. Exploitable over UDP where there's no rate limiting on HEP packets.

**Fix:** Constant-time compare. Also consider rate-limiting HEP auth failures per source IP.

---

### F10: Medium — XFF Trusted for Rate Limiting

**File:** `core/main.mko` lines 2724-2728  
**Code:** Rate limiter uses `http_header(c, "X-Forwarded-For")` as the client IP.

An attacker can set arbitrary `X-Forwarded-For` headers to bypass rate limiting by rotating spoofed IPs. When behind nginx this is partially mitigated (nginx overwrites XFF), but the core can be accessed directly if port 9090 is exposed.

**Fix:** Only trust XFF when a `ZAMAN_TRUSTED_PROXIES` list is configured. Fall back to the TCP peer address. The web dashboard has the same issue (line 1532-1540) but for IP allowlisting, where spoofed XFF could bypass the allowlist entirely.

---

### F11: Medium — Session Cookie Missing `Secure` Flag

**File:** `web/main.weft` line 180  
**Code:** `"zaman_sid=" + token + "; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax"`

When deployed behind TLS (the recommended production config), the cookie should include the `Secure` flag to prevent transmission over HTTP.

**Fix:** Add `Secure` flag when `ZAMAN_TLS=1` or when `X-Forwarded-Proto: https` is detected. Consider also setting `__Host-` prefix for additional protection.

---

### F12: Medium — User/Token Files Readable at Rest

**Files:** `data/zaman-users.json`, `data/zaman-api-tokens.json`

User password hashes (even weak SHA-256 ones) and API token hashes are stored in plain JSON files. File permissions are set to 750 on the data directory by the installer, but the zaman process user can read them. Any file-read vulnerability or log exposure could leak these.

**Fix:** The installer correctly sets `chmod 750`. Ensure the web process doesn't serve the data directory. Add a check that `data/` is not under the web root. Consider encrypting sensitive fields at rest.

---

### F13: Low — Weak Password Policy

**File:** `web/main.weft` lines 1514-1526  
8 characters + 1 digit is below modern standards (NIST SP 800-63B recommends checking against breached password lists).

**Fix:** Increase minimum to 12 characters. Consider checking against a top-10k breached passwords list.

---

### F14: Low — No Login Brute-Force Protection

**File:** `web/main.weft` lines 1869-1880  
Failed logins are audited but not rate-limited. An attacker can attempt unlimited password guesses.

**Fix:** Add per-IP and per-username rate limiting (e.g., 5 attempts per minute). Lock accounts after 10 consecutive failures with admin unlock required.

---

### F15: Low — Installer Supply Chain

**File:** `install.sh` lines 117-143  
The installer runs `curl | bash` from `mako-lang.dev/install.sh` and downloads binaries from multiple fallback URLs without checksum verification.

**Fix:** Pin expected SHA-256 checksums for binaries. Verify GPG signatures if available. Use `--proto =https` with curl.

---

### F16: Low — Partials Endpoints Skip Auth

**File:** `web/main.weft` lines 1967-2007  
`/partials/status`, `/partials/charts`, `/partials/nodes`, `/partials/messages` do not call `get_user()`. They return HTML fragments that could leak node names, message counts, and traffic patterns to unauthenticated users.

`/partials/alerts` (line 2814) also skips auth and additionally fires alert notifications on every poll, meaning an unauthenticated client could trigger webhook floods.

**Fix:** Add auth checks to all partials endpoints, or gate them behind a middleware.

---

### F17: Low — CSRF Relies on SameSite=Lax Only

POST actions (user creation, deletion, password reset, alert configuration) use HTML forms without CSRF tokens. SameSite=Lax prevents cross-site form submissions in modern browsers, but older browsers or certain redirect-based attacks may bypass this.

**Fix:** Add a CSRF token to state-changing forms. A per-session random value in a hidden field, verified on POST, is sufficient.

---

## What v0.2 Got Right

Credit where due -- these are solid security decisions:

1. **SIP credential redaction** (`redact_sip()`) strips Authorization headers before storage.
2. **Probe SSRF protections** block metadata endpoints (169.254.169.254), private IPs by default, and cap timeout to 5s.
3. **API key auth** on the core with rate limiting (configurable req/s per IP).
4. **HEP password + IP allowlist** for ingest authentication.
5. **HTML escaping** via `h()` is consistently applied across the dashboard.
6. **`sql_quote()`** handles single-quote escaping for SQL parameters.
7. **`sanitize_cid()`** blocks path traversal in recording filenames.
8. **RBAC enforcement** is checked on every route (admin/operator/viewer).
9. **Audit logging** with rotation for compliance.
10. **HMAC-signed stateless sessions** avoid server-side session storage attacks.
11. **API tokens stored as SHA-256 hashes** (not plaintext).
12. **SIP echo policy** defaults to OPTIONS-only, REGISTER returns 401 (not fake 200).

---

## Hardening Recommendations

### Immediate (before any internet exposure)

1. **Replace SHA-256 password hashing with bcrypt/Argon2id** (F1).
2. **Add auth to `/recordings/:cid`** (F5).
3. **Add auth to `/partials/*` endpoints** (F16).
4. **Add file size limit to recording upload** (F4, e.g., reject > 50MB).

### Short-term (before production)

5. **Constant-time comparison** for all secret comparisons (F2, F8, F9).
6. **Persist the token secret** to survive restarts (F6).
7. **Add the `Secure` cookie flag** when behind TLS (F11).
8. **Login rate limiting** -- 5 attempts/minute per IP (F14).
9. **Validate federation push records** (F3).
10. **Only trust XFF from configured proxy IPs** (F10).

### Longer-term

11. **CSRF tokens** on all state-changing forms (F17).
12. **Checksum verification** in the installer (F15).
13. **Stronger password policy** (F13).
14. **ClickHouse parameterized queries** (F7).
15. **Mutual TLS for federation peers**.

---

## Security Configuration Reference

| Variable | Purpose | Default | Recommendation |
|----------|---------|---------|----------------|
| `ZAMAN_API_KEY` | Core API authentication | *(none -- open)* | Always set. 48+ hex chars. |
| `ZAMAN_AUTH` | Dashboard auth toggle | `1` (on) | Never set to `0` in production. |
| `ZAMAN_HEP_PASSWORD` | HEP ingest password | *(none -- open)* | Set for all deployments accepting HEP. |
| `ZAMAN_HEP_ALLOW` | HEP source IP allowlist | *(any)* | Set to known agent IPs. |
| `ZAMAN_DASHBOARD_ALLOW_IPS` | Dashboard IP allowlist | *(any)* | Set for internal/VPN deployments. |
| `ZAMAN_PROBE` | Enable active probing | `0` (off) | Keep off unless needed. |
| `ZAMAN_PROBE_ALLOW_PRIVATE` | Allow probing RFC1918 | `0` (off) | Keep off. |
| `ZAMAN_ECHO_METHODS` | SIP echo method filter | `OPTIONS` | Keep default. Never set `ALL`. |
| `ZAMAN_ECHO_ALL` | Echo all SIP methods | `0` (off) | Keep off in production. |
| `ZAMAN_RATE_LIMIT` | API req/s per IP | `100` | Lower to 20-50 for public deployments. |
| `ZAMAN_DB_RETENTION_DAYS` | Auto-purge captures | `14` | Set per compliance requirements. |
| `ZAMAN_HEP_TLS` | HEP TLS listener | `0` (off) | Enable for WAN HEP agents. |

### Nginx hardening (add to `/etc/nginx/conf.d/zaman.conf`)

```nginx
# Block direct access to core API from outside
location /api/ {
    allow 127.0.0.1;
    deny all;
    proxy_pass http://127.0.0.1:9090/api/;
}

# Security headers
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Content-Security-Policy "default-src 'self' https://cdn.jsdelivr.net; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" always;
```

### Firewall (verify after install)

```bash
# Core API should NOT be internet-accessible
ufw deny from any to any port 9090
# Only allow HEP from known agents
ufw allow from 10.0.0.0/8 to any port 9060 proto udp
```
