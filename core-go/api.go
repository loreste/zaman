package main

import (
	"context"
	"database/sql"
	json2 "encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rateLimiter tracks per-IP request counts.
type apiRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]int
	second  int64
}

func newAPIRateLimiter() *apiRateLimiter {
	return &apiRateLimiter{buckets: make(map[string]int)}
}

func (rl *apiRateLimiter) allow(ip string, max int) bool {
	if max <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	sec := time.Now().Unix()
	if sec != rl.second {
		rl.buckets = make(map[string]int)
		rl.second = sec
	}
	rl.buckets[ip]++
	return rl.buckets[ip] <= max
}

func clientIP(r *http.Request, trusted string) string {
	if trusted != "" {
		remote, _, _ := net.SplitHostPort(r.RemoteAddr)
		if remote == trusted {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.SplitN(xff, ",", 2)
				return strings.TrimSpace(parts[0])
			}
			if xri := r.Header.Get("X-Real-IP"); xri != "" {
				return xri
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func queryGet(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// apiWorker runs the HTTP API server.
func apiWorker(ctx context.Context, db *sql.DB, cfg *Config, metrics *Metrics, ring *Ring, cache *Cache, dbCh chan<- string) {
	rl := newAPIRateLimiter()
	mux := http.NewServeMux()

	// Auth middleware
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if cfg.APIKey != "" {
				key := r.Header.Get("X-API-Key")
				if key == "" {
					auth := r.Header.Get("Authorization")
					if strings.HasPrefix(auth, "Bearer ") {
						key = auth[7:]
					}
				}
				if !constantTimeEqual(key, cfg.APIKey) {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	// Rate limit middleware
	withRateLimit := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, cfg.TrustedProxy)
			if !rl.allow(ip, cfg.RateLimit) {
				http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
				return
			}
			next(w, r)
		}
	}

	json := func(w http.ResponseWriter, data string) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(data))
	}

	// ---- Health ----
	mux.HandleFunc("/health", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		// Basic health always available
		if cfg.APIKey != "" {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					key = auth[7:]
				}
			}
			if !constantTimeEqual(key, cfg.APIKey) {
				json(w, `{"ok":true}`)
				return
			}
		}
		// Detailed health
		metrics.mu.Lock()
		uptime := time.Since(metrics.StartTime).Milliseconds()
		dbOk := metrics.DBOk
		dbErr := metrics.DBErr
		dbDrop := metrics.DBDrop
		metrics.mu.Unlock()

		var captures int64
		db.QueryRow("SELECT reltuples::bigint FROM pg_class WHERE relname='captures'").Scan(&captures)

		json(w, fmt.Sprintf(`{"ok":true,"service":"zaman-core","version":"%s","uptime_ms":%d,"db":{"driver":"%s","writes_ok":%d,"writes_err":%d,"writes_dropped":%d},"retention":{"days":%d,"cutoff_ms":%d,"enabled":%t},"captures":%d,"channel_capacity":4096}`,
			Version, uptime, cfg.DBDriver, dbOk, dbErr, dbDrop,
			cfg.RetentionDays, time.Now().Add(-time.Duration(cfg.RetentionDays)*24*time.Hour).UnixMilli(),
			cfg.RetentionDays > 0, captures))
	}))
	// /api/health is just an alias
	mux.HandleFunc("/api/health", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		if cfg.APIKey != "" {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					key = auth[7:]
				}
			}
			if !constantTimeEqual(key, cfg.APIKey) {
				json(w, `{"ok":true}`)
				return
			}
		}
		metrics.mu.Lock()
		uptime := time.Since(metrics.StartTime).Milliseconds()
		dbOk := metrics.DBOk
		dbErr := metrics.DBErr
		dbDrop := metrics.DBDrop
		metrics.mu.Unlock()
		var captures int64
		db.QueryRow("SELECT reltuples::bigint FROM pg_class WHERE relname='captures'").Scan(&captures)
		json(w, fmt.Sprintf(`{"ok":true,"service":"zaman-core","version":"%s","uptime_ms":%d,"db":{"driver":"%s","writes_ok":%d,"writes_err":%d,"writes_dropped":%d},"retention":{"days":%d,"cutoff_ms":%d,"enabled":%t},"captures":%d,"channel_capacity":4096}`,
			Version, uptime, cfg.DBDriver, dbOk, dbErr, dbDrop,
			cfg.RetentionDays, time.Now().Add(-time.Duration(cfg.RetentionDays)*24*time.Hour).UnixMilli(),
			cfg.RetentionDays > 0, captures))
	}))

	// ---- Metrics ----
	mux.HandleFunc("/api/metrics", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		metrics.mu.Lock()
		uptime := time.Since(metrics.StartTime).Milliseconds()
		msgsTotal := metrics.MsgsTotal
		dbOk := metrics.DBOk
		dbErr := metrics.DBErr
		dbDrop := metrics.DBDrop
		requests := metrics.Requests
		responses := metrics.Responses
		echoes := metrics.Echoes
		hepTotal := metrics.HEPTotal
		hepUDP := metrics.HEPUDP
		hepTCP := metrics.HEPTCP
		hepTLS := metrics.HEPTLS
		hepErr := metrics.HEPErr
		hepAuthFail := metrics.HEPAuthFail
		hepDeny := metrics.HEPDeny
		hepSIP := metrics.HEPSIP
		hepRTCP := metrics.HEPRTCP
		hepRTP := metrics.HEPRTP
		hepRTCPXR := metrics.HEPRTCPXR
		hepOther := metrics.HEPOther
		parseErr := metrics.ParseErr
		s2xx := metrics.Status2xx
		s4xx5xx := metrics.Status4xx5xx
		methods := make(map[string]int64)
		for k, v := range metrics.Methods {
			methods[k] = v
		}
		metrics.mu.Unlock()

		var methodParts []string
		for k, v := range methods {
			methodParts = append(methodParts, fmt.Sprintf(`"%s":%d`, jesc(k), v))
		}

		json(w, fmt.Sprintf(`{"service":"zaman-core","version":"%s","uptime_ms":%d,"msgs_total":%d,"db_ok":%d,"db_err":%d,"db_drop":%d,"requests":%d,"responses":%d,"echoes":%d,"hep_total":%d,"hep_udp":%d,"hep_tcp":%d,"hep_tls":%d,"hep_err":%d,"hep_auth_fail":%d,"hep_deny":%d,"hep_sip":%d,"hep_rtcp":%d,"hep_rtp":%d,"hep_rtcpxr":%d,"hep_other":%d,"parse_err":%d,"status_2xx":%d,"status_4xx_5xx":%d,"methods":{%s}}`,
			Version, uptime, msgsTotal, dbOk, dbErr, dbDrop,
			requests, responses, echoes,
			hepTotal, hepUDP, hepTCP, hepTLS, hepErr, hepAuthFail, hepDeny,
			hepSIP, hepRTCP, hepRTP, hepRTCPXR, hepOther,
			parseErr, s2xx, s4xx5xx,
			strings.Join(methodParts, ",")))
	})))

	// Prometheus
	mux.HandleFunc("/metrics", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		metrics.mu.Lock()
		uptime := time.Since(metrics.StartTime).Milliseconds()
		mt := metrics.MsgsTotal
		dok := metrics.DBOk
		derr := metrics.DBErr
		ddrop := metrics.DBDrop
		ht := metrics.HEPTotal
		req := metrics.Requests
		resp := metrics.Responses
		ech := metrics.Echoes
		metrics.mu.Unlock()

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "zaman_up 1\nzaman_uptime_ms %d\nzaman_messages_total %d\nzaman_db_ok %d\nzaman_db_err %d\nzaman_db_dropped %d\nzaman_hep_total %d\nzaman_requests %d\nzaman_responses %d\nzaman_echoes %d\n",
			uptime, mt, dok, derr, ddrop, ht, req, resp, ech)
	})))

	// ---- Messages ----
	mux.HandleFunc("/api/messages", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 300)
		callID := queryGet(r, "call_id")
		transport := queryGet(r, "transport")
		agent := queryGet(r, "agent")
		method := queryGet(r, "method")
		src := queryGet(r, "ip")
		if src == "" {
			src = queryGet(r, "src")
		}
		from := queryGet(r, "from_number")
		to := queryGet(r, "to_number")
		status := queryGet(r, "status")
		sinceMs := queryGet(r, "since_ms")
		untilMs := queryGet(r, "until_ms")
		state := queryGet(r, "state")

		json(w, buildMessagesJSON(db, limit, callID, transport, agent, method, src, from, to, status, sinceMs, untilMs, state))
	})))

	// Single message by ID: /api/messages/12345
	mux.HandleFunc("/api/messages/", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		idStr := strings.TrimPrefix(r.URL.Path, "/api/messages/")
		if idStr == "" {
			json(w, "null")
			return
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			json(w, "null")
			return
		}
		row := db.QueryRow(`SELECT id, ts_ms, src, dst, transport, proto, agent, kind, method, status,
			call_id, from_h, to_h, cseq, ruri, hep_node_id, hep_node, hep_cid, size, raw_b64
			FROM captures WHERE id=$1`, id)
		var mid, tsMs int64
		var src, dst, transport, proto, agent, kind, method string
		var status, hepNodeID, size int
		var callID, fromH, toH, cseq, ruri, hepNode, hepCID, rawB64 string
		if err := row.Scan(&mid, &tsMs, &src, &dst, &transport, &proto, &agent, &kind, &method, &status,
			&callID, &fromH, &toH, &cseq, &ruri, &hepNodeID, &hepNode, &hepCID, &size, &rawB64); err != nil {
			json(w, "null")
			return
		}
		json(w, fmt.Sprintf(
			`{"id":%d,"ts_ms":%d,"src":"%s","dst":"%s","transport":"%s","proto":"%s","agent":"%s","kind":"%s","method":"%s","status":%d,"call_id":"%s","from_h":"%s","to_h":"%s","cseq":"%s","ruri":"%s","hep_node_id":%d,"hep_node":"%s","hep_cid":"%s","size":%d,"raw_b64":"%s"}`,
			mid, tsMs, jesc(src), jesc(dst), jesc(transport), jesc(proto), jesc(agent),
			jesc(kind), jesc(method), status, jesc(callID), jesc(fromH), jesc(toH),
			jesc(cseq), jesc(ruri), hepNodeID, jesc(hepNode), jesc(hepCID), size, jesc(rawB64)))
	})))

	// ---- Report endpoints ----
	mux.HandleFunc("/api/report", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildReportSummaryJSON(db))
	})))
	mux.HandleFunc("/api/report/summary", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildReportSummaryJSON(db))
	})))
	mux.HandleFunc("/api/report/daily", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildDailyJSON(db, queryInt(r, "limit", 14)))
	})))
	mux.HandleFunc("/api/report/top-calls", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildTopCallsJSON(db, queryInt(r, "limit", 20),
			queryGet(r, "agent"), queryGet(r, "state"),
			queryGet(r, "src"), queryGet(r, "dst"),
			queryGet(r, "from_number"), queryGet(r, "to_number")))
	})))
	mux.HandleFunc("/api/report/top-talkers", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if j, ok := cache.Get("top_talkers"); ok && queryGet(r, "limit") == "" {
			json(w, j)
			return
		}
		json(w, buildTopTalkersJSON(db, queryInt(r, "limit", 20)))
	})))
	mux.HandleFunc("/api/report/agents", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if j, ok := cache.Get("agents"); ok {
			json(w, j)
			return
		}
		json(w, buildAgentsJSON(db))
	})))
	mux.HandleFunc("/api/report/kpi", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// Use cached realtime (1-min) for speed — KPI page uses this
		if j, ok := cache.Get("realtime"); ok {
			json(w, j)
			return
		}
		json(w, buildRealtimeJSON(db, cfg, 1, ""))
	})))
	mux.HandleFunc("/api/report/response-codes", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildResponseCodesJSON(db))
	})))
	mux.HandleFunc("/api/report/cps", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildCPSJSON(db, queryInt(r, "minutes", 60)))
	})))

	// ---- Realtime ----
	mux.HandleFunc("/api/realtime", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		window := queryInt(r, "window", 5)
		agent := queryGet(r, "agent")
		if window <= 1 && agent == "" {
			if j, ok := cache.Get("realtime"); ok {
				json(w, j)
				return
			}
		}
		json(w, buildRealtimeJSON(db, cfg, window, agent))
	})))

	// ---- Calls ----
	mux.HandleFunc("/api/calls/active", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 50)
		agent := queryGet(r, "agent")
		state := queryGet(r, "state")
		src := queryGet(r, "src")
		dst := queryGet(r, "dst")
		from := queryGet(r, "from_number")
		to := queryGet(r, "to_number")

		if agent == "" && state == "" && src == "" && dst == "" && from == "" && to == "" {
			if j, ok := cache.Get("calls"); ok {
				json(w, j)
				return
			}
		}
		json(w, buildActiveCallsJSON(db, cfg, limit, agent, state, src, dst, from, to))
	})))

	// ---- Nodes ----
	mux.HandleFunc("/api/nodes", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if j, ok := cache.Get("nodes"); ok {
			json(w, j)
			return
		}
		json(w, buildNodesJSON(db, cfg))
	})))

	// ---- SLA ----
	mux.HandleFunc("/api/sla/agents", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if j, ok := cache.Get("sla_agents"); ok {
			json(w, j)
			return
		}
		json(w, buildSLAAgentsJSON(db, cfg))
	})))
	mux.HandleFunc("/api/sla/destinations", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildSLADestJSON(db, cfg))
	})))
	mux.HandleFunc("/api/sla/sources", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildSLASrcJSON(db, cfg))
	})))
	mux.HandleFunc("/api/sla/carrier", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildCarrierScoreJSON(db, queryGet(r, "ip")))
	})))

	// ---- GeoIP lookup (cached, uses ip-api.com free tier) ----
	geoCache := &sync.Map{}
	mux.HandleFunc("/api/geoip", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		ip := queryGet(r, "ip")
		if ip == "" {
			json(w, `{"error":"ip required"}`)
			return
		}
		// Check cache
		if cached, ok := geoCache.Load(ip); ok {
			json(w, cached.(string))
			return
		}
		// Lookup (ip-api.com free, 45 req/min)
		resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=status,country,regionName,city,lat,lon,isp,org,as")
		if err != nil {
			json(w, `{"error":"lookup failed"}`)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		result := string(body)
		geoCache.Store(ip, result)
		json(w, result)
	})))

	// ---- Anomalies ----
	mux.HandleFunc("/api/anomalies", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildAnomaliesJSON(db))
	})))

	// ---- Historical trends ----
	mux.HandleFunc("/api/trend/daily", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildTrendJSON(db, queryInt(r, "days", 14)))
	})))
	mux.HandleFunc("/api/trend/hourly", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, buildHourlyTrendJSON(db, queryInt(r, "hours", 24)))
	})))

	// ---- Number/DID search ----
	mux.HandleFunc("/api/number", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		number := queryGet(r, "q")
		if number == "" {
			json(w, `{"error":"q required"}`)
			return
		}
		json(w, buildNumberJSON(db, cfg, number))
	})))

	// ---- CSV export ----
	mux.HandleFunc("/api/export/csv", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		callID := queryGet(r, "call_id")
		agent := queryGet(r, "agent")
		src := queryGet(r, "ip")
		limit := queryInt(r, "limit", 500)
		msgs := buildMessagesJSON(db, limit, callID, "", agent, "", src, "", "", "", "", "", "")
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=zaman-export.csv")
		// Parse JSON array and write CSV
		var records []map[string]interface{}
		json2.Unmarshal([]byte(msgs), &records)
		w.Write([]byte("timestamp,method,status,call_id,src,dst,agent,transport\n"))
		for _, rec := range records {
			ts := ""
			if t, ok := rec["ts_ms"].(float64); ok {
				ts = time.Unix(int64(t)/1000, 0).Format("2006-01-02 15:04:05")
			}
			fmt.Fprintf(w, "%s,%s,%v,%s,%s,%s,%s,%s\n",
				ts, csvField(rec["method"]), rec["status"],
				csvField(rec["call_id"]), csvField(rec["src"]), csvField(rec["dst"]),
				csvField(rec["agent"]), csvField(rec["transport"]))
		}
	})))

	// ---- Webhook alerts ----
	alertConfigFile := filepath.Join(env("ZAMAN_DATA_DIR", "data"), "zaman-alert-config.json")
	mux.HandleFunc("/api/alerts/config", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			data, err := os.ReadFile(alertConfigFile)
			if err != nil {
				json(w, `{"webhooks":[],"thresholds":{"asr_min":70,"err_rate_max":10}}`)
				return
			}
			w.Write(data)
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
			os.MkdirAll(filepath.Dir(alertConfigFile), 0o755)
			os.WriteFile(alertConfigFile, body, 0o600)
			json(w, `{"ok":true}`)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})))

	// ---- Delete ----
	mux.HandleFunc("/api/delete", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		callID := queryGet(r, "call_id")
		beforeTs := queryGet(r, "before_ts")
		if callID != "" {
			db.Exec("DELETE FROM captures WHERE call_id=$1", callID)
			db.Exec("DELETE FROM call_state WHERE call_id=$1", callID)
			json(w, `{"ok":true}`)
		} else if beforeTs != "" {
			ts, _ := strconv.ParseInt(beforeTs, 10, 64)
			if ts > 0 {
				db.Exec("DELETE FROM captures WHERE ts_ms < $1", ts)
				db.Exec("DELETE FROM call_state WHERE last_ts_ms < $1", ts)
				json(w, `{"ok":true}`)
			}
		} else {
			json(w, `{"error":"call_id or before_ts required"}`)
		}
	})))

	// ---- Related calls ----
	mux.HandleFunc("/api/related", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		callID := queryGet(r, "call_id")
		if callID == "" {
			json(w, "[]")
			return
		}
		var parts []string
		seen := map[string]bool{callID: true}

		// Method 1: same hep_cid (HEP correlation ID — best signal)
		rows1, err := db.Query(`SELECT DISTINCT call_id FROM captures WHERE hep_cid=(SELECT hep_cid FROM captures WHERE call_id=$1 AND hep_cid != '' LIMIT 1) AND call_id != $1 LIMIT 10`, callID)
		if err == nil {
			defer rows1.Close()
			for rows1.Next() {
				var cid string
				rows1.Scan(&cid)
				if !seen[cid] {
					seen[cid] = true
					parts = append(parts, fmt.Sprintf(`{"call_id":"%s","reason":"hep_correlation"}`, jesc(cid)))
				}
			}
		}

		// Method 2: same From+To within 30s window (B2BUA re-INVITE pattern)
		rows2, err := db.Query(`
			SELECT DISTINCT cs2.call_id FROM call_state cs1
			JOIN call_state cs2 ON cs2.call_id != cs1.call_id
				AND cs2.from_h = cs1.from_h AND cs2.to_h = cs1.to_h
				AND abs(cs2.first_ts_ms - cs1.first_ts_ms) < 30000
			WHERE cs1.call_id = $1 LIMIT 10`, callID)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var cid string
				rows2.Scan(&cid)
				if !seen[cid] {
					seen[cid] = true
					parts = append(parts, fmt.Sprintf(`{"call_id":"%s","reason":"from_to_match"}`, jesc(cid)))
				}
			}
		}

		// Method 3: same From+To reversed (outbound leg of B2BUA)
		rows3, err := db.Query(`
			SELECT DISTINCT cs2.call_id FROM call_state cs1
			JOIN call_state cs2 ON cs2.call_id != cs1.call_id
				AND cs2.from_h = cs1.to_h AND cs2.to_h = cs1.from_h
				AND abs(cs2.first_ts_ms - cs1.first_ts_ms) < 30000
			WHERE cs1.call_id = $1 LIMIT 10`, callID)
		if err == nil {
			defer rows3.Close()
			for rows3.Next() {
				var cid string
				rows3.Scan(&cid)
				if !seen[cid] {
					seen[cid] = true
					parts = append(parts, fmt.Sprintf(`{"call_id":"%s","reason":"b2bua_leg"}`, jesc(cid)))
				}
			}
		}

		json(w, "["+strings.Join(parts, ",")+"]")
	})))

	// ---- Export ----
	mux.HandleFunc("/api/export", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		callID := queryGet(r, "call_id")
		json(w, buildMessagesJSON(db, 500, callID, "", "", "", "", "", "", "", "", "", ""))
	})))

	// ---- QoS ----
	mux.HandleFunc("/api/qos", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		callID := queryGet(r, "call_id")
		if callID == "" {
			json(w, "[]")
			return
		}
		json(w, buildQoSJSON(db, callID))
	})))

	// ---- Stats ----
	mux.HandleFunc("/api/stats", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to metrics
		mux.ServeHTTP(w, r)
	})))

	// ---- Probe ----
	mux.HandleFunc("/api/probe", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		json(w, doProbe(cfg, metrics, string(body)))
	})))

	// ---- Federation ----
	mux.HandleFunc("/api/federation/health", withRateLimit(func(w http.ResponseWriter, r *http.Request) {
		json(w, `{"ok":true,"federation":true}`)
	}))
	mux.HandleFunc("/api/federation/push", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, `{"ok":true,"accepted":0}`) // TODO: implement
	})))

	// ---- Grafana ----
	mux.HandleFunc("/api/grafana/", withRateLimit(requireAuth(func(w http.ResponseWriter, r *http.Request) {
		json(w, `{"ok":true}`)
	})))

	// ---- Static files (SPA) ----
	staticDir := cfg.StaticDir
	if _, err := os.Stat(staticDir); err != nil {
		staticDir = "web/static"
		if _, err := os.Stat(staticDir); err != nil {
			staticDir = filepath.Join(filepath.Dir(os.Args[0]), "..", "web", "static")
		}
	}
	fs := http.FileServer(http.Dir(staticDir))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Block path traversal
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Try real file, fall back to index.html for SPA routing
		path := filepath.Join(staticDir, r.URL.Path)
		if r.URL.Path != "/" && r.URL.Path != "" {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				r.URL.Path = "/"
			}
		}
		fs.ServeHTTP(w, r)
	})

	// Start server
	addr := fmt.Sprintf(":%d", cfg.APIPort)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("api: listening on %s", addr)

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("api: %v", err)
	}
}
