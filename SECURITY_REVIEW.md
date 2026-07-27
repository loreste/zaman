# Zaman Security Review (White-Hat)

**Scope:** read-only review of Zaman SIP monitoring (v0.1)  
**Primary artifacts:** `core/main.mko`, `web/main.weft`, `scripts/*`, `README.md`, `Makefile`  
**Date:** 2026-07-27  
**Mode:** offensive-minded, defensive outcomes — no code was modified for exploitation

---

## Executive summary

Zaman v0.1 is an integrated SIP capture / echo / HEP / metrics stack with an HTMX dashboard. The roadmap correctly lists **auth as unfinished**, but several design choices make an internet- or LAN-exposed deployment dangerous *today*:

1. **Unauthenticated read/write of VoIP metadata and raw SIP** (including credential-bearing headers) via the HTTP API and dashboard.
2. **Unauthenticated active probing** (`POST /api/probe`) that turns the host into a **network-scanner / SIP flooder / SSRF-like internal recon tool**, with **no host allowlist**, **no rate limit**, and an **unbounded timeout** that **blocks the only HTTP worker**.
3. **Open UDP SIP echo** for `OPTIONS` / `REGISTER` / `INFO` / `MESSAGE` (and all methods if `ZAMAN_ECHO_ALL=1`) without authentication — a **reflector**, false-registration oracle, and MESSAGE spam amplifier.
4. **Unauthenticated HEP ingest** allowing forged call metadata into the ring store and dashboards.
5. **Default bind-all** (`0.0.0.0` SIP/HEP; API/web print localhost but listen more broadly) with **no TLS, no auth, no rate limiting**.

Dashboard HTML escaping is generally conscientious (`h()` / `html.escape`). That reduces XSS risk but does **not** mitigate data exposure, SSRF-class probe abuse, or open SIP services. Several JSON-construction paths are incomplete (`jesc`), and `do_probe` never closes its ephemeral UDP socket.

**Bottom line:** treat Zaman as a **lab / trusted-network tool only**. Do not expose SIP, HEP, API, or dashboard ports to untrusted networks until auth, probe controls, and echo policy are fixed.

---

## Threat model assumptions

| Actor | Access | Goals |
|-------|--------|--------|
| Untrusted SIP peer | UDP to SIP port (default 5060, binds `0.0.0.0`) | Reflect traffic, spam REGISTER/MESSAGE, fill ring with junk, DoS |
| Untrusted HEP peer | UDP to HEP port (default 9060) | Inject forged call metadata / raw SIP into store |
| Untrusted HTTP client | TCP to API (default 9090) and/or dashboard (3000) | Exfil call metadata + raw SIP; SSRF/scan via probe; DoS API |
| Insider / multi-tenant co-tenant | Shared network with Zaman | Same as above plus silent recon of other tenants via probe |
| Malicious SIP payload author | Controls headers/bodies that later render in UI / JSON API | JSON breakout, XSS, filter bypass, consumer crashes |

**Out of scope / not fully validated:** Mako/Weft runtime memory safety, `http_bind` exact interface binding, CMap concurrency guarantees, and whether `html.escape` encodes all HTML-significant codepoints. Items needing runtime confirmation are marked **needs validation**.

**Assumed defaults:** process started with no args → SIP `0.0.0.0:5060`, HEP same host `:9060`, API `:9090`, web `:3000`, `ZAMAN_ECHO_ALL=0`.

---

## Critical/High findings

### H1 — Critical: Unauthenticated API exposes full SIP captures (including secrets)

**Severity:** Critical  

**Attack scenario:**  
Any client that can reach the API port can list recent messages and fetch full records including `raw_b64` (entire SIP message). REGISTER/INVITE traffic often carries `Authorization` / `Proxy-Authorization` (Digest passwords hashes, or worse, cleartext credentials), `P-Asserted-Identity`, numbers, and SDP. An attacker exfiltrates call metadata and auth material without credentials.

**Evidence:**
- No auth checks in `http_worker` — every path responds openly:

```646:688:core/main.mko
        if str_eq(path, "/health") || str_eq(path, "/api/health") {
            let body = "{\"ok\":true,\"service\":\"zaman-core\",\"version\":\"" + VERSION + "\"}"
            let _ = http_respond_json(c, 200, body)
        } else if str_eq(path, "/api/metrics") {
            ...
        } else if str_eq(path, "/api/messages") {
            ...
        } else if str_has_prefix(path, "/api/messages/") {
            ...
        } else if str_eq(path, "/api/probe") && str_eq(method, "POST") {
            ...
```

- Full message stored and exported as base64 of **complete** SIP:

```139:158:core/main.mko
    let raw_b64 = base64_encode(msg)
    ...
    j = j + ",\"raw_b64\":\"" + raw_b64 + "\""
```

- README documents open endpoints and deferred auth (`README.md` Core API table; roadmap “Auth on dashboard / API” unchecked).

**Fix recommendation:**
1. Require authentication on all non-health endpoints (API key / mTLS / reverse-proxy auth). Prefer bind API to `127.0.0.1` by default when used only by local Weft.
2. Redact sensitive headers (`Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, cookie-like headers) before store **and** before export; optional “raw mode” behind elevated role.
3. Separate scrape credentials for `/metrics` (or network-restrict Prometheus).
4. Document that v0.1 has **no** confidentiality guarantee.

---

### H2 — Critical: Unauthenticated dashboard is a full control plane over the same data + probe

**Severity:** Critical  

**Attack scenario:**  
Browser or curl to `:3000` (or wherever Weft listens) yields Overview, Messages, Call ladder, Metrics, and **Echo probe** with no login. The web app server-side-fetches the core and renders raw SIP after base64 decode. Same data-exfil as H1, plus a UI for probing arbitrary hosts.

**Evidence:**
- All routes open in `web/main.weft` (`app.get("/")`, `/messages`, `/messages/:id`, `/probe`, `app.post("/probe")`, etc.).
- `app.listen(":3000")` — host not restricted to loopback.
- Probe form posts user-controlled host/port to core:

```350:355:web/main.weft
    app.post("/probe", fn(req) {
        host := web.form_get(req, "host", "127.0.0.1")
        port := int.parse(web.form_get(req, "port", "5060")).unwrap_or(0)
        wait_ms := int.parse(web.form_get(req, "timeout_ms", "2000")).unwrap_or(0)
        payload := json.stringify({"host": host, "port": port, "timeout_ms": wait_ms})
        resp := http.post(core_base() + "/api/probe", payload, {"headers": {"Content-Type": "application/json"}})
```

**Fix recommendation:**
1. AuthN/AuthZ on Weft (session/cookie + CSRF on POST `/probe`).
2. Bind dashboard to `127.0.0.1` by default; put behind reverse proxy with TLS in production.
3. Disable or hide probe in production builds unless explicitly enabled.

---

### H3 — Critical: `POST /api/probe` is an open network scanner / SIP emitter (SSRF-class)

**Severity:** Critical  

**Attack scenario:**  
Attacker (or anyone who can hit API or dashboard probe form) POSTs:

```json
{"host":"10.0.0.5","port":5060,"timeout_ms":5000}
```

Zaman binds an ephemeral UDP socket and sends a crafted SIP OPTIONS to **any** host:port. Impacts:

- **Internal recon:** map which IPs/ports speak SIP (status codes / RTT).
- **Cross-tenant / cloud metadata-adjacent abuse:** scan RFC1918, link-local, cloud VPC neighbors (**needs validation** whether runtime resolves hostnames and follows anything beyond UDP SIP — still dangerous for lateral SIP mapping).
- **SIP flood:** many probe requests → many OPTIONS to a victim (abuse of Zaman as attack proxy).
- **CSRF from dashboard:** no CSRF token on `POST /probe`.

**Evidence:**

```495:547:core/main.mko
fn do_probe(metrics: CMap, host: string, port: int, wait_ms: int) -> string {
    let fd = sip_udp_bind("0.0.0.0", 0)
    ...
    let opts = sip_request("OPTIONS", "sip:echo@" + host + ":" + string(port), h, "")
    ...
    let sent = sip_udp_send(fd, host, port, opts)
    ...
    while waited < wait_ms {
        let resp = sip_udp_recv(fd, 65535)
        ...
    }
```

```667:682:core/main.mko
        } else if str_eq(path, "/api/probe") && str_eq(method, "POST") {
            let body = http_body(c)
            let mut host = json_get_string(body, "host")
            let mut port_p = json_get_int(body, "port")
            let mut wait_ms = json_get_int(body, "timeout_ms")
            ...
            let result = do_probe(metrics, host, port_p, wait_ms)
```

No allowlist, denylist (localhost / link-local / metadata IPs), auth, or rate limit. Port only checked `<= 0` (defaults to 5060); no upper bound check to 65535.

**Fix recommendation:**
1. **Disable probe by default**; enable with `ZAMAN_PROBE=1`.
2. Allowlist destinations (CIDR / exact hosts); block private/link-local/metadata ranges unless `ZAMAN_PROBE_ALLOW_PRIVATE=1`.
3. Cap `timeout_ms` (e.g. 50–5000), cap concurrent probes, rate-limit per source IP.
4. Require auth + CSRF for dashboard-triggered probes.
5. Log every probe with client identity.

---

### H4 — High: Probe blocks the sole HTTP accept loop (API DoS) + unbounded timeout

**Severity:** High  

**Attack scenario:**  
HTTP worker is a single sequential loop: `http_accept` → handle → `http_close`. `do_probe` runs **inline** for up to `wait_ms` with a busy-wait (`sleep_ms(5)`). Attacker sets:

```json
{"host":"203.0.113.1","port":9,"timeout_ms":2147483647}
```

`wait_ms` only defaults when `<= 0`; **no maximum**. One request can freeze `/api/health`, `/api/messages`, `/metrics`, and further probes for a very long time. Even with modest timeouts, concurrent attackers serialize the API.

**Evidence:**

```629:689:core/main.mko
fn http_worker(...) {
    ...
    while 1 == 1 {
        let c = http_accept(fd)
        ...
            let result = do_probe(metrics, host, port_p, wait_ms)
            let _ = http_respond_json(c, 200, result)
        ...
        let _ = http_close(c)
    }
}
```

```678:680:core/main.mko
            if wait_ms <= 0 {
                wait_ms = 2000
            }
```

**Fix recommendation:**
1. Hard-cap `timeout_ms` (e.g. `min(wait_ms, 5000)`).
2. Run probes on a worker pool / separate thread; never block accept loop.
3. Reject new probes when one is in flight (or queue with limit).
4. Use blocking recv with SO_RCVTIMEO instead of busy-poll if available.

---

### H5 — High: Open SIP echo (REGISTER 200 unauthenticated, MESSAGE, OPTIONS) — reflector & abuse

**Severity:** High  

**Attack scenario:**
1. **UDP reflection:** Attacker spoofs source IP of OPTIONS/REGISTER/MESSAGE to victim; Zaman replies 200 OK to the victim (classic SIP reflection; amp factor modest but still open responder).
2. **False registration success:** Any REGISTER gets **200 OK + Expires: 3600** with no credentials check — scanners/clients may believe they registered; operational confusion; potential policy bypass if something trusts “registered to Zaman”.
3. **MESSAGE spam:** Auto-200 for MESSAGE encourages abuse and stores MESSAGE bodies in the ring for later exfil via API.
4. **`ZAMAN_ECHO_ALL=1`:** Echoes **all** requests (including INVITE) with 200 — can disrupt real call setups if mis-deployed on a shared path.

**Evidence:**

```173:208:core/main.mko
fn should_echo(msg: string, echo_all: int) -> int {
    ...
    if sip_method_eq(msg, "OPTIONS") == 1 { return 1 }
    if sip_method_eq(msg, "REGISTER") == 1 { return 1 }
    if sip_method_eq(msg, "INFO") == 1 { return 1 }
    if sip_method_eq(msg, "MESSAGE") == 1 { return 1 }
    return 0
}
...
    if sip_method_eq(msg, "REGISTER") == 1 {
        let exp = sip_headers_append(extra3, "Expires", "3600")
        return sip_reply(msg, 200, "OK", exp, "")
    }
```

```316:325:core/main.mko
        if should_echo(msg, echo_all) == 1 {
            let reply = build_echo(msg, local_host, local_port)
            let host = udp_last_sender_host()
            let port = udp_last_sender_port()
            if not str_eq(host, "") && port > 0 {
                let _ = sip_udp_send(fd, host, port, reply)
```

Default bind:

```697:697:core/main.mko
    let mut sip_host = env_get_or("ZAMAN_SIP_HOST", "0.0.0.0")
```

**Fix recommendation:**
1. Default echo **off** or OPTIONS-only; make REGISTER/MESSAGE opt-in (`ZAMAN_ECHO_METHODS=OPTIONS`).
2. For REGISTER: respond `401`/`403` or `200` only with explicit lab mode; never advertise real registration success without auth.
3. Rate-limit echoes per source IP; optional require shared secret / allowlisted peers.
4. Do not enable `ZAMAN_ECHO_ALL` outside isolated labs; document blast radius.
5. Prefer binding SIP to specific interface; firewall by default.

---

### H6 — High: Unauthenticated HEP ingest → forged telemetry & ring pollution

**Severity:** High  

**Attack scenario:**  
Anyone who can UDP to HEP port sends HEPv3 with arbitrary payload chunk (type 0x000f). Payload is parsed as SIP and stored with attacker-chosen src IP/port and agent id. Impacts: fake call ladders, false incidents, injection of malicious SIP text into dashboards/API for other analysts, ring eviction of real traffic (DoS of visibility).

**Evidence:**

```338:358:core/main.mko
fn handle_hep_packet(store: CMap, metrics: CMap, pkt: string) {
    let info = hep_decode(pkt)
    ...
    let rec = make_record(src, "HEP3", info.payload, agent)
    cap_push(store, metrics, rec)
```

No HEP shared secret, TLS, or source allowlist. `hep_decode` accepts any `HEP3` framing with a payload chunk.

**Fix recommendation:**
1. Shared secret / HMAC HEP auth (Homer-style) or mTLS on a TCP HEP path.
2. Allowlist HEP agent IPs.
3. Separate retention quotas for HEP vs native SIP.
4. Default HEP bind to localhost if only local agents exist.

---

## Medium findings

### M1 — Medium: Resource leak in `do_probe` (UDP sockets never closed)

**Severity:** Medium  

**Attack scenario:**  
Each probe calls `sip_udp_bind("0.0.0.0", 0)` and returns without closing `fd` (success, send-fail, and timeout paths). Repeated probes exhaust file descriptors; subsequent binds fail; SIP/HEP workers may also fail if FD table fills (**needs validation** of runtime FD limits and whether Mako GC closes sockets).

**Evidence:** `do_probe` in `core/main.mko` ~495–547 — no `close`/`sip_udp_close` on any path.

**Fix recommendation:**  
Always close the probe socket in a finally-equivalent path; prefer one reusable probe socket with serialized use.

---

### M2 — Medium: Incomplete JSON escaping (`jesc`) — injection / parser confusion

**Severity:** Medium  

**Attack scenario:**  
SIP headers (From, To, Call-ID, etc.) are attacker-controlled. `jesc` only escapes `\`, `"`, `\r`, `\n`, `\t`. Missing: other C0 controls (`\u0000`–`\u001f`), `\b`, `\f`, U+2028/U+2029. A header containing raw bytes can:

- Break strict JSON parsers (API clients, Weft `http.get_json`).
- Truncate or confuse C-string based consumers on `\0`.
- Cause subtle dashboard failures (empty tables) which is availability impact.

`raw_b64` is not passed through `jesc`; standard Base64 alphabet is JSON-safe (OK if encoder is strict).

**Evidence:**

```12:18:core/main.mko
fn jesc(s: string) -> string {
    let mut o = str_replace(s, "\\", "\\\\")
    o = str_replace(o, "\"", "\\\"")
    o = str_replace(o, "\r", "\\r")
    o = str_replace(o, "\n", "\\n")
    o = str_replace(o, "\t", "\\t")
    return o
}
```

**Fix recommendation:**  
Implement full JSON string escaping (all controls as `\u00XX`). Prefer a single JSON builder primitive from the runtime if available. Fuzz with random SIP headers.

---

### M3 — Medium: Call-ID filter is substring match over whole JSON record (incl. `raw_b64`)

**Severity:** Medium  

**Attack scenario:**  
Filter uses `str_contains(rec, "\"call_id\":\"" + jesc(call_id_filter) + "\"")` on the entire serialized record. Impact:

- Substring false positives (`ab` matches `abc`).
- Filter string may match inside `raw_b64` or other fields if the JSON substring appears coincidentally — information-leak / confusion; attackers can craft SIP so Call-ID filtering becomes unreliable.
- Query string is **not URL-decoded** in `query_get` — `%xx` not normalized.

**Evidence:**

```458:466:core/main.mko
            let keep = if str_eq(call_id_filter, "") {
                1
            } else {
                if str_contains(rec, "\"call_id\":\"" + jesc(call_id_filter) + "\"") {
                    1
                } else {
                    0
                }
            }
```

**Fix recommendation:**  
Parse fields into structured storage; exact-match Call-ID; URL-decode query params.

---

### M4 — Medium: Binding defaults & misleading localhost messaging

**Severity:** Medium  

**Attack scenario:**  
Operators read logs / README “http://127.0.0.1:PORT” and believe the API is loopback-only. Code uses `http_bind(port)` (no host) and SIP/HEP default `0.0.0.0`. Web listens on `":3000"`. Accidental exposure on multi-homed hosts / cloud VMs is likely.

**Evidence:**
- `ZAMAN_SIP_HOST` default `0.0.0.0` (`core/main.mko` ~697).
- `print("api  http http://127.0.0.1:" + string(port))` (~634) while bind is port-only (~629).
- `app.listen(":3000")` (`web/main.weft` ~424).
- README documents `0.0.0.0` for SIP host but API/web exposure is under-emphasized.

**Fix recommendation:**  
Default all listeners to `127.0.0.1`; require `ZAMAN_*_HOST=0.0.0.0` to go public; log actual bind address; fix print strings.

---

### M5 — Medium: No rate limiting on SIP / HEP / HTTP

**Severity:** Medium  

**Attack scenario:**  
Flood UDP SIP or HEP to force CPU parse + ring overwrite (visibility DoS) + echo replies (outbound bandwidth). Flood HTTP for connection churn. Combine with H4 for total monitoring outage.

**Evidence:** No rate-limit counters or token buckets in workers; ring only bounds memory to ~512 slots, not CPU/bandwidth.

**Fix recommendation:**  
Per-source rate limits; global PPS caps; drop + metric when exceeded; optional fail2ban-style temp bans.

---

### M6 — Medium: Capture ring concurrent access race (sip + hep + http)

**Severity:** Medium (**needs validation** of CMap atomicity)

**Attack scenario:**  
`sip_worker`, `hep_worker`, and `http_worker` share `store`/`metrics`. `cap_push` does non-atomic read-modify-write of `idx` and slot write. If CMap ops are not atomic across threads, possible torn reads, lost messages, or wrong id mapping — integrity failure for forensics.

**Evidence:**

```66:72:core/main.mko
fn cap_push(ring: CMap, metrics: CMap, rec: string) {
    let idx = cmap_i(ring, "idx")
    let slot = idx % RING
    cmap_set(ring, "msg_" + string(slot), rec)
    cmap_set_i(ring, "idx", idx + 1)
    ...
}
```

Workers kicked concurrently in `crew t` (~722–729).

**Fix recommendation:**  
Document CMap concurrency; if not atomic, use a mutex or single writer thread with queues.

---

### M7 — Medium: CSRF / clickjacking on probe (dashboard)

**Severity:** Medium  

**Attack scenario:**  
Authenticated-user scenario after auth is added — or any browser on a network that can reach open dashboard today. Malicious page auto-POSTs `/probe` via HTMX/form to force OPTIONS against internal targets. No CSRF token, no `SameSite` session cookies (no sessions yet), no `X-Frame-Options` / CSP.

**Evidence:** `app.post("/probe")` form without token (`web/main.weft` ~338–355).

**Fix recommendation:**  
CSRF tokens; `SameSite=strict` cookies when auth lands; CSP; `frame-ancestors 'none'`.

---

## Low/Info findings

### L1 — Low: Message id path handling is integer-only (path traversal largely mitigated)

**Severity:** Low / Info  

`/api/messages/:id` uses `path[14:]` + `parse_int_or`. Non-numeric ids fail closed to 404. Web route `/messages/:id` concatenates id into core URL — **needs validation** that Weft param cannot contain `/` or `?` for open proxy path abuse; likely single path segment.

**Fix:** Explicit integer validation; reject non-`^[0-9]+$`.

---

### L2 — Low: URL query construction without `encodeURIComponent` (web → core)

**Severity:** Low  

`fetch_messages` appends `call_id` raw (`web/main.weft` ~136–138). Call-IDs with `&`, `=`, spaces break filters; not classic SSRF (host fixed by `ZAMAN_CORE`).

**Fix:** URL-encode query parameters.

---

### L3 — Low: HTML attribute vs URL context mixing

**Severity:** Low  

Call-IDs are HTML-escaped (`h()`) then placed in `href` / `hx-get` query strings. Good against XSS attribute breakout; can mangle URLs for special characters. Prefer: URL-encode for URLs, HTML-escape for text nodes.

**Evidence:** e.g. `href="/calls?call_id=" + cid` with `cid := h(call_id)` (`web/main.weft` ~89–99, ~278, ~314).

---

### L4 — Low: Numeric fields rendered without `h()` in some places

**Severity:** Low  

`id`, `status`, `rtt` sometimes concatenated as `"" + (id)`. If JSON types are always numbers from core, safe. If a compromised/buggy core returned strings with HTML, risk rises. Defense-in-depth: always `h()`.

---

### L5 — Info: Third-party CDN scripts (supply chain)

**Severity:** Info  

Tailwind browser CDN (`cdn.jsdelivr.net`) and HTMX CDN in layout. Compromised CDN → XSS on dashboard.

**Fix:** Pin SRI hashes, self-host assets.

---

### L6 — Info: Demo/smoke scripts use high ports but still open services

**Severity:** Info  

`demo.sh` / `smoke.sh` use 15060/19060/19090 and curl localhost — good for local lab. Core still binds SIP to `0.0.0.0` by default even in demo. Smoke does not test auth, probe restrictions, or REGISTER behavior.

---

### L7 — Info: Prometheus metrics are mostly safe from injection

**Severity:** Info (positive-leaning)  

Metric names/labels are code-defined counters, not SIP-derived label values — low Prometheus injection risk. `/metrics` remains unauthenticated information disclosure (traffic volumes, probe RTT).

---

### L8 — Info: README honesty vs residual overconfidence

**Severity:** Info  

README correctly lists auth as TODO. Residual false confidence:

- Log line implies API is `127.0.0.1` only.
- “production-ish ports” language without production security controls.
- Echo of REGISTER as 200 may be read as intentional SIP server behavior rather than lab convenience.

---

### L9 — Info: Mild amplification via echo replies

**Severity:** Low  

Small OPTIONS request → larger 200 with Contact/Server/Allow. Not a classic large amp factor, but open internet exposure still enables reflection nuisance.

---

### L10 — Info: Memory bounded by ring, not by single message policy

**Severity:** Info  

`RING = 512`, UDP recv up to 65535. Worst-case resident payload on order of tens of MB if every slot holds max-size messages — acceptable for v0.1 but worth documenting. No max body size policy for stored SIP beyond UDP limit.

---

## Positive controls (what is done right)

1. **Dashboard XSS posture is strong overall** — dedicated `h()` helper wrapping `html.escape` used for Call-ID, From, To, raw SIP text, probe errors, etc.
2. **Raw SIP display path** decodes base64 then escapes before `<pre>` (`web/main.weft` ~291–313).
3. **HEP does not auto-echo** — only stores; no HEP-triggered reflection.
4. **Messages list limit capped** at 200 (`messages_json`).
5. **Ring size fixed** — prevents unbounded capture growth.
6. **Prometheus series are static** — no user-controlled label injection surface in `metrics_prom`.
7. **Roadmap admits missing auth** — reduces “false product security” claim (good honesty).
8. **Demo/smoke prefer high ports and 127.0.0.1 clients** — healthier local defaults than blindly using 5060 in scripts.
9. **`jesc` handles the common JSON breakout characters** (`\`, `"`, newlines) even if incomplete.
10. **Probe accepts only SIP responses on ephemeral socket** — reduces some cross-talk; still not a security boundary.

---

## Recommended fix order (priority patch list)

| Priority | Item | Effort | Risk reduced |
|----------|------|--------|--------------|
| P0 | Bind API + web to `127.0.0.1` by default; document firewall for SIP/HEP | Small | Accidental exposure |
| P0 | Disable or heavily gate `POST /api/probe` (flag + allowlist + auth) | Small–Med | SSRF/scanner/flood |
| P0 | Cap `timeout_ms`; never block HTTP accept on probe; close probe FD | Small | API DoS + FD leak |
| P0 | Auth on API + dashboard (or reverse-proxy only deployment guide) | Med | Data exfil |
| P1 | Redact Authorization* headers in store/export | Small | Credential leak |
| P1 | Echo policy: OPTIONS-only default; REGISTER must not 200 as registered without auth | Small | Reflector / false auth |
| P1 | HEP allowlist / shared secret | Med | Forged telemetry |
| P2 | Full JSON escape; structured records instead of string contains filter | Med | Injection / integrity |
| P2 | Rate limits on SIP/HEP/HTTP | Med | DoS |
| P2 | CSRF + CSP + CDN SRI | Small | Web abuse |
| P3 | CMap concurrency audit / mutex | Med | Race integrity |
| P3 | URL-encoding of query params in Weft | Small | Correctness |

**Minimal “don’t get owned tomorrow” checklist:**

```text
1. Firewall: deny WAN → 5060/9060/9090/3000
2. export ZAMAN_SIP_HOST=127.0.0.1   # if local only
3. Do not set ZAMAN_ECHO_ALL=1 on shared networks
4. Do not publish /api/probe without auth + allowlist
5. Put nginx/caddy with basic auth or mTLS in front of 9090/3000
```

---

## Residual risk if nothing is fixed

If Zaman is reachable by untrusted parties with current defaults:

- **Confidentiality:** All recent SIP (up to 512 messages), including auth headers and MESSAGE bodies, is world-readable via HTTP.
- **Integrity:** HEP and SIP sources can forge monitoring data; analysts cannot trust ladders/metrics.
- **Availability:** Probe timeout DoS freezes the API; UDP floods churn CPU and overwrite the ring; FD leak from probes can brick the process over time.
- **Abuse / liability:** Host becomes an open SIP OPTIONS/REGISTER/MESSAGE responder and an on-demand SIP scanner against third parties — network abuse complaints, reflection participation, and lateral recon from a “monitoring” box.
- **Compliance:** Call metadata/PII capture without access control may violate privacy expectations even on internal VoIP.

With **network isolation only** (no code fixes): risk drops sharply for internet attackers but **remains high for any local multi-tenant user, compromised laptop on the same LAN, or SSRF into the host**. Isolation is necessary but not sufficient for multi-user environments.

---

## Appendix A — Endpoint exposure matrix

| Surface | Default | Auth | Notes |
|---------|---------|------|-------|
| SIP UDP | `0.0.0.0:5060` | None | Capture + echo |
| HEP UDP | `0.0.0.0:9060` | None | Ingest only |
| API HTTP | `:9090` (host unspecified) | None | Full read + probe |
| Dashboard | `:3000` all interfaces | None | UI + probe proxy |
| `/metrics` | on API | None | Counters only |

## Appendix B — False confidence map

| Looks safe | Reality |
|------------|---------|
| Log “API http://127.0.0.1:…” | Bind is not obviously loopback-restricted |
| `jesc` present | Incomplete vs JSON RFC; control chars slip through |
| HTML escaping everywhere important | Prevents XSS ≠ prevents data theft or probe SSRF |
| Ring size 512 | Bounds memory, not exfil of the last N sensitive messages |
| README “auth TODO” | Accurate, but defaults still “production-ish ports” |
| Probe “only OPTIONS” | Still full UDP reachability test + flood vector |
| REGISTER 200 + Expires | Looks like a registrar; is unauthenticated lab echo |

## Appendix C — Key code references

| Topic | Location |
|-------|----------|
| `jesc` | `core/main.mko` 12–18 |
| Record / `raw_b64` | `core/main.mko` 97–159 |
| Echo policy + REGISTER 200 | `core/main.mko` 173–208, 316–325 |
| HEP decode/ingest | `core/main.mko` 222–291, 338–358 |
| Probe | `core/main.mko` 495–547, 667–682 |
| HTTP routes | `core/main.mko` 629–691 |
| Defaults / bind host | `core/main.mko` 696–730 |
| Dashboard `h()` / routes / probe | `web/main.weft` 8–10, 241–424 |
| Demo ports | `scripts/demo.sh`, `scripts/smoke.sh` |

---

*End of report. This review did not run dynamic exploits against live systems; classifications marked “needs validation” should be confirmed with runtime tests under a controlled lab.*

---

## Mitigations applied after this review (same session)

| Finding | Mitigation landed |
|---------|-------------------|
| H3 probe open by default | `ZAMAN_PROBE` default **0**; 403 when disabled |
| H4 unbounded timeout | Cap **5000 ms** on probe wait |
| M1 probe FD leak | `udp_close(fd)` on all probe paths |
| H5 REGISTER false success | Default echo **OPTIONS only**; REGISTER → **401** if enabled |
| H1 partial secret leak | `Authorization` / `Proxy-Authorization` **redacted** before store |
| M2 incomplete jesc | Control bytes → `\u00XX` |
| Misleading API log | Log warns **NO AUTH** / bind `0.0.0.0` |

| TLS mid-session abort | TLS sessions inline (no `drain(0)` kill); read → close TLS → parse |
| `for s in range ch` broken | Mako 0.4.17 codegen fix; `db_writer` uses `for j in range ch` |

**Still open (do not claim fixed):** full API/dashboard authentication, HEP allowlist, rate limits, CMap races, CSRF, loopback-only `http_bind` (runtime API is port-only), SSRF private-range allowlist beyond metadata IP.