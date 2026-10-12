package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// buildTrendJSON returns daily ASR/ACD/volume for historical analysis.
// Uses report_daily + call_state for up to 30 days even with short capture retention.
func buildTrendJSON(db *sql.DB, days int) string {
	if days <= 0 || days > 90 {
		days = 14
	}
	cutoffMs := time.Now().Add(-time.Duration(days) * 24 * time.Hour).UnixMilli()

	// Daily call metrics from call_state (survives longer than captures)
	rows, err := db.Query(fmt.Sprintf(`
		SELECT (first_ts_ms / 86400000) AS day_bucket,
			count(*) AS total,
			count(*) FILTER (WHERE answered=1) AS answered,
			count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400) AS failed,
			COALESCE(round(avg((last_ts_ms-answer_ts_ms)/1000.0) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms>0 AND last_ts_ms>answer_ts_ms)),0) AS acd
		FROM call_state WHERE first_ts_ms >= %d
		GROUP BY day_bucket ORDER BY day_bucket`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var bucket, total, answered, failed, acd int64
		rows.Scan(&bucket, &total, &answered, &failed, &acd)
		completed := answered + failed
		asr := int64(0)
		if completed > 0 {
			asr = answered * 100 / completed
			if asr > 100 { asr = 100 }
		}
		// Convert bucket back to date string
		day := time.Unix(bucket*86400, 0).UTC().Format("2006-01-02")
		parts = append(parts, fmt.Sprintf(
			`{"day":"%s","total":%d,"answered":%d,"failed":%d,"asr":%d,"acd":%d}`,
			day, total, answered, failed, asr, acd))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildHourlyTrendJSON returns hourly metrics for the last N hours.
func buildHourlyTrendJSON(db *sql.DB, hours int) string {
	if hours <= 0 || hours > 168 {
		hours = 24
	}
	cutoffMs := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()

	rows, err := db.Query(fmt.Sprintf(`
		SELECT (first_ts_ms / 3600000) AS hour_bucket,
			count(*) AS total,
			count(*) FILTER (WHERE answered=1) AS answered,
			count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400) AS failed,
			COALESCE(round(avg((last_ts_ms-answer_ts_ms)/1000.0) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms>0 AND last_ts_ms>answer_ts_ms)),0) AS acd
		FROM call_state WHERE first_ts_ms >= %d
		GROUP BY hour_bucket ORDER BY hour_bucket`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var bucket, total, answered, failed, acd int64
		rows.Scan(&bucket, &total, &answered, &failed, &acd)
		completed := answered + failed
		asr := int64(0)
		if completed > 0 {
			asr = answered * 100 / completed
			if asr > 100 { asr = 100 }
		}
		ts := bucket * 3600000
		parts = append(parts, fmt.Sprintf(
			`{"ts":%d,"total":%d,"answered":%d,"failed":%d,"asr":%d,"acd":%d}`,
			ts, total, answered, failed, asr, acd))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func csvField(v interface{}) string {
	s := fmt.Sprintf("%v", v)
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// buildNumberJSON returns call history for a phone number.
func buildNumberJSON(db *sql.DB, cfg *Config, number string) string {
	cutoffMs := time.Now().Add(-60 * time.Minute).UnixMilli()
	q := sqlQuote(number)

	// Find calls involving this number
	rows, err := db.Query(fmt.Sprintf(`
		SELECT call_id, agent, first_ts_ms, last_ts_ms, answered, open, last_status,
			src, dst, from_h, to_h, answer_ts_ms
		FROM call_state
		WHERE first_ts_ms >= %d AND (from_h LIKE '%%%s%%' OR to_h LIKE '%%%s%%')
		ORDER BY first_ts_ms DESC LIMIT 50`, cutoffMs, q, q))
	if err != nil {
		return fmt.Sprintf(`{"number":"%s","calls":[],"total":0}`, jesc(number))
	}
	defer rows.Close()

	var calls []string
	var total, answered, failed int64
	var durations []int64
	for rows.Next() {
		var callID, agent, src, dst, fromH, toH string
		var firstTs, lastTs, answerTs int64
		var ans, open, lastStatus int
		rows.Scan(&callID, &agent, &firstTs, &lastTs, &ans, &open, &lastStatus,
			&src, &dst, &fromH, &toH, &answerTs)
		total++
		if ans == 1 {
			answered++
			if answerTs > 0 && lastTs > answerTs {
				durations = append(durations, (lastTs-answerTs)/1000)
			}
		}
		if ans == 0 && open == 0 && lastStatus >= 400 {
			failed++
		}
		state := "ringing"
		if open == 0 && ans == 1 {
			state = "completed"
		} else if open == 0 {
			state = "failed"
		} else if ans == 1 {
			state = "in_progress"
		}
		calls = append(calls, fmt.Sprintf(
			`{"call_id":"%s","agent":"%s","first_ts_ms":%d,"last_ts_ms":%d,"state":"%s","status":%d,"src":"%s","dst":"%s","from":"%s","to":"%s"}`,
			jesc(callID), jesc(agent), firstTs, lastTs, state, lastStatus,
			jesc(src), jesc(dst), jesc(fromH), jesc(toH)))
	}

	asr := int64(0)
	completed := answered + failed
	if completed > 0 {
		asr = answered * 100 / completed
	}
	acd := int64(0)
	if len(durations) > 0 {
		sum := int64(0)
		for _, d := range durations {
			sum += d
		}
		acd = sum / int64(len(durations))
	}

	return fmt.Sprintf(`{"number":"%s","total":%d,"answered":%d,"failed":%d,"asr":%d,"acd":%d,"calls":[%s]}`,
		jesc(number), total, answered, failed, asr, acd, strings.Join(calls, ","))
}

// likeOrRegex returns a WHERE clause fragment. If value starts with /, use PG regex (~).
func likeOrRegex(col, value string) string {
	if strings.HasPrefix(value, "/") {
		return fmt.Sprintf(" AND %s ~ '%s'", col, sqlQuote(value[1:]))
	}
	return fmt.Sprintf(" AND %s LIKE '%%%s%%'", col, sqlQuote(value))
}

// buildRealtimeJSON generates realtime stats for a given time window.
func buildRealtimeJSON(db *sql.DB, cfg *Config, windowMin int, agentFilter string) string {
	cutoffMs := time.Now().Add(-time.Duration(windowMin) * time.Minute).UnixMilli()

	agentWhere := ""
	if agentFilter != "" {
		agentWhere = fmt.Sprintf(" AND agent='%s'", sqlQuote(agentFilter))
	}

	// Message counts
	var total, invites, inviteMsgs, byes, registers, options int64
	var resp2xx, resp4xx, resp5xx int64
	var err401, err403, err404, err486, err503 int64

	row := db.QueryRow(fmt.Sprintf(`SELECT
		COALESCE(count(*),0),
		COALESCE(count(*) FILTER (WHERE method='INVITE' AND kind='request'),0),
		COALESCE(count(*) FILTER (WHERE method LIKE '%%INVITE%%'),0),
		COALESCE(count(*) FILTER (WHERE method='BYE' OR method LIKE '%%BYE%%'),0),
		COALESCE(count(*) FILTER (WHERE method='REGISTER' OR method LIKE '%%REGISTER%%'),0),
		COALESCE(count(*) FILTER (WHERE method='OPTIONS' OR method LIKE '%%OPTIONS%%'),0),
		COALESCE(count(*) FILTER (WHERE status >= 200 AND status < 300),0),
		COALESCE(count(*) FILTER (WHERE status >= 400 AND status < 500),0),
		COALESCE(count(*) FILTER (WHERE status >= 500),0),
		COALESCE(count(*) FILTER (WHERE status = 401),0),
		COALESCE(count(*) FILTER (WHERE status = 403),0),
		COALESCE(count(*) FILTER (WHERE status = 404),0),
		COALESCE(count(*) FILTER (WHERE status = 486),0),
		COALESCE(count(*) FILTER (WHERE status = 503),0)
		FROM captures WHERE ts_ms >= %d%s`, cutoffMs, agentWhere))

	row.Scan(&total, &invites, &inviteMsgs, &byes, &registers, &options,
		&resp2xx, &resp4xx, &resp5xx,
		&err401, &err403, &err404, &err486, &err503)

	// Active calls from call_state
	activeWhere := activeCallWhere(cfg)
	agentCallWhere := ""
	if agentFilter != "" {
		agentCallWhere = fmt.Sprintf(" AND agent='%s'", sqlQuote(agentFilter))
	}

	var activeCalls, openDialogs, staleOpen int64
	db.QueryRow(fmt.Sprintf("SELECT COALESCE(count(*),0) FROM call_state WHERE %s%s",
		activeWhere, agentCallWhere)).Scan(&activeCalls)
	db.QueryRow(fmt.Sprintf("SELECT COALESCE(count(*),0) FROM call_state WHERE open=1%s",
		agentCallWhere)).Scan(&openDialogs)
	staleOpen = openDialogs - activeCalls
	if staleOpen < 0 {
		staleOpen = 0
	}

	// Unique agents and sources
	var agentsActive, sources int64
	db.QueryRow(fmt.Sprintf("SELECT COALESCE(count(DISTINCT agent),0) FROM captures WHERE ts_ms >= %d%s",
		cutoffMs, agentWhere)).Scan(&agentsActive)
	db.QueryRow(fmt.Sprintf("SELECT COALESCE(count(DISTINCT src),0) FROM captures WHERE ts_ms >= %d%s AND method='INVITE' AND kind='request'",
		cutoffMs, agentWhere)).Scan(&sources)

	// ASR / NER / ACD from call_state
	var answered, failed, acdSec, acdCalls int64
	db.QueryRow(fmt.Sprintf(`SELECT
		COALESCE(count(*) FILTER (WHERE answered=1),0),
		COALESCE(count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400),0),
		COALESCE(CASE WHEN count(*) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms > 0 AND last_ts_ms > answer_ts_ms) > 0
			THEN round(avg((last_ts_ms - answer_ts_ms)/1000.0) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms > 0 AND last_ts_ms > answer_ts_ms)) ELSE 0 END, 0),
		COALESCE(count(*) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms > 0 AND last_ts_ms > answer_ts_ms), 0)
		FROM call_state WHERE first_ts_ms >= %d%s`,
		cutoffMs, agentCallWhere)).Scan(&answered, &failed, &acdSec, &acdCalls)

	totalCalls := answered + failed
	asr := int64(0)
	ner := int64(0)
	errRate := int64(0)
	if totalCalls > 0 {
		asr = answered * 100 / totalCalls
		ner = (totalCalls - failed) * 100 / totalCalls
	}
	allResp := resp2xx + resp4xx + resp5xx
	if allResp > 0 {
		errRate = (resp4xx + resp5xx) * 100 / allResp
	}

	return fmt.Sprintf(`{"window_min":%d,"agent":"%s","total":%d,"invites":%d,"invite_messages":%d,"byes":%d,"registers":%d,"options":%d,"resp_2xx":%d,"resp_4xx":%d,"resp_5xx":%d,"err_401":%d,"err_403":%d,"err_404":%d,"err_486":%d,"err_503":%d,"active_calls":%d,"concurrent_calls":%d,"open_dialogs":%d,"stale_open_dialogs":%d,"active_cutoff_sec":%d,"ringing_cutoff_sec":%d,"agents_active":%d,"sources":%d,"answered_calls":%d,"failed_calls":%d,"edge_rejects":0,"acd_seconds":%d,"acd_calls":%d,"asr":%d,"ner":%d,"err_rate":%d}`,
		windowMin, jesc(agentFilter), total, invites, inviteMsgs, byes, registers, options,
		resp2xx, resp4xx, resp5xx, err401, err403, err404, err486, err503,
		activeCalls, activeCalls, openDialogs, staleOpen,
		cfg.ConcurrentCallMaxAge, cfg.RingingMaxAge,
		agentsActive, sources, answered, failed, acdSec, acdCalls, asr, ner, errRate)
}

// buildNodesJSON generates per-agent health data.
func buildNodesJSON(db *sql.DB, cfg *Config) string {
	cutoffMs := time.Now().Add(-5 * time.Minute).UnixMilli()
	nowMs := time.Now().UnixMilli()

	rows, err := db.Query(fmt.Sprintf(`
		SELECT agent,
			count(*) AS total,
			count(*) AS recent,
			max(ts_ms) AS last_seen,
			count(DISTINCT call_id) AS calls,
			count(*) FILTER (WHERE status >= 400) AS errors
		FROM captures WHERE ts_ms >= %d
		GROUP BY agent ORDER BY total DESC`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var agent string
		var total, recent, lastSeen, calls, errors int64
		rows.Scan(&agent, &total, &recent, &lastSeen, &calls, &errors)

		ageSec := (nowMs - lastSeen) / 1000
		status := "green"
		if ageSec > 300 {
			status = "red"
		} else if ageSec > 60 {
			status = "yellow"
		}

		// Active calls for this agent
		var activeCalls int64
		db.QueryRow(fmt.Sprintf("SELECT COALESCE(count(*),0) FROM call_state WHERE %s AND agent='%s'",
			activeCallWhere(cfg), sqlQuote(agent))).Scan(&activeCalls)

		parts = append(parts, fmt.Sprintf(
			`{"agent":"%s","total":%d,"recent":%d,"last_seen":%d,"age_sec":%d,"calls":%d,"active_calls":%d,"errors":%d,"status":"%s"}`,
			jesc(agent), total, recent, lastSeen, ageSec, calls, activeCalls, errors, status))
	}

	return "[" + strings.Join(parts, ",") + "]"
}

// buildActiveCallsJSON generates active/recent calls list.
func buildActiveCallsJSON(db *sql.DB, cfg *Config, limit int, agent, state, src, dst, from, to string) string {
	where := "1=1"
	if agent != "" {
		where += fmt.Sprintf(" AND agent='%s'", sqlQuote(agent))
	}
	if src != "" {
		where += fmt.Sprintf(" AND src LIKE '%%%s%%'", sqlQuote(src))
	}
	if dst != "" {
		where += fmt.Sprintf(" AND dst LIKE '%%%s%%'", sqlQuote(dst))
	}
	if from != "" {
		where += fmt.Sprintf(" AND from_h LIKE '%%%s%%'", sqlQuote(from))
	}
	if to != "" {
		where += fmt.Sprintf(" AND to_h LIKE '%%%s%%'", sqlQuote(to))
	}

	// State filter
	switch state {
	case "open", "ringing":
		where += " AND open=1 AND answered=0"
	case "answered", "active":
		where += " AND open=1 AND answered=1"
	case "ended":
		where += " AND open=0"
	case "failed":
		where += " AND open=0 AND answered=0 AND last_status >= 400"
	case "canceled":
		where += " AND open=0 AND last_method LIKE '%CANCEL%'"
	}

	if limit <= 0 || limit > 500 {
		limit = 50
	}

	rows, err := db.Query(fmt.Sprintf(`
		SELECT call_id, agent, first_ts_ms, last_ts_ms, last_id, invite_id,
			last_method, last_status, answered, open,
			src, dst, from_h, to_h, answer_ts_ms
		FROM call_state WHERE %s
		ORDER BY last_ts_ms DESC LIMIT %d`, where, limit))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var callID, agent, lastMethod, src, dst, fromH, toH string
		var firstTs, lastTs, lastID, inviteID, answerTs int64
		var lastStatus, answered, open int
		rows.Scan(&callID, &agent, &firstTs, &lastTs, &lastID, &inviteID,
			&lastMethod, &lastStatus, &answered, &open,
			&src, &dst, &fromH, &toH, &answerTs)

		callState := "ended"
		if open == 1 && answered == 1 {
			callState = "answered"
		} else if open == 1 {
			callState = "ringing"
		} else if answered == 0 && lastStatus >= 400 {
			callState = "failed"
		}

		// Estimate message count from id range (fast, no subquery)
		msgCount := lastID - inviteID
		if msgCount < 1 { msgCount = 1 }
		reqCount := msgCount / 2
		respCount := msgCount - reqCount

		parts = append(parts, fmt.Sprintf(
			`{"id":%d,"call_id":"%s","ts_ms":%d,"ts_first":%d,"ts_last":%d,"src":"%s","dst":"%s","from":"%s","to":"%s","from_h":"%s","to_h":"%s","agent":"%s","transport":"HEP3","method":"INVITE","status":%d,"kind":"request","state":"%s","messages":%d,"requests":%d,"responses":%d,"answered":%d,"open":%d,"last_status":%d,"first_ts_ms":%d}`,
			lastID, jesc(callID), lastTs, firstTs, lastTs,
			jesc(src), jesc(dst), jesc(fromH), jesc(toH), jesc(fromH), jesc(toH),
			jesc(agent), lastStatus, callState,
			msgCount, reqCount, respCount, answered, open, lastStatus, firstTs))
	}

	return "[" + strings.Join(parts, ",") + "]"
}

// buildTopTalkersJSON returns top source IPs.
func buildTopTalkersJSON(db *sql.DB, limit int) string {
	rows, err := db.Query(fmt.Sprintf(`
		SELECT src, count(*) AS messages, count(DISTINCT call_id) AS calls
		FROM (SELECT src, call_id FROM captures ORDER BY id DESC LIMIT 50000) sub
		GROUP BY src ORDER BY messages DESC LIMIT %d`, limit))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var src string
		var messages, calls int64
		rows.Scan(&src, &messages, &calls)
		parts = append(parts, fmt.Sprintf(
			`{"src":"%s","messages":%d,"calls":%d,"source":"recent"}`,
			jesc(src), messages, calls))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildAgentsJSON returns per-agent summary.
func buildAgentsJSON(db *sql.DB) string {
	rows, err := db.Query(`
		SELECT agent, count(*) AS messages, count(DISTINCT call_id) AS calls,
			min(ts_ms) AS first_seen, max(ts_ms) AS last_seen
		FROM (SELECT agent, call_id, ts_ms FROM captures ORDER BY id DESC LIMIT 50000) sub
		GROUP BY agent ORDER BY messages DESC`)
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var agent string
		var messages, calls, firstSeen, lastSeen int64
		rows.Scan(&agent, &messages, &calls, &firstSeen, &lastSeen)
		parts = append(parts, fmt.Sprintf(
			`{"agent":"%s","messages":%d,"calls":%d,"first_seen":%d,"last_seen":%d,"source":"recent"}`,
			jesc(agent), messages, calls, firstSeen, lastSeen))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildReportSummaryJSON returns overall report summary.
func buildReportSummaryJSON(db *sql.DB) string {
	var total int64
	db.QueryRow("SELECT COALESCE(sum(cnt),0) FROM report_daily").Scan(&total)

	// Use fast estimates instead of full table scans
	var tsMin, tsMax sql.NullInt64
	db.QueryRow("SELECT min(first_ts_ms), max(last_ts_ms) FROM call_state").Scan(&tsMin, &tsMax)

	var uniqueCalls int64
	db.QueryRow("SELECT reltuples::bigint FROM pg_class WHERE relname='call_state'").Scan(&uniqueCalls)

	// Method breakdown from report_daily
	rows, err := db.Query(`
		SELECT method, COALESCE(sum(cnt),0) FROM report_daily
		GROUP BY method ORDER BY sum(cnt) DESC LIMIT 30`)
	methods := ""
	if err == nil {
		defer rows.Close()
		var mparts []string
		for rows.Next() {
			var method string
			var cnt int64
			rows.Scan(&method, &cnt)
			mparts = append(mparts, fmt.Sprintf(`"%s":%d`, jesc(method), cnt))
		}
		methods = strings.Join(mparts, ",")
	}

	return fmt.Sprintf(`{"total":%d,"unique_call_ids":%d,"hep":%d,"sip_udp":0,"ts_min":%d,"ts_max":%d,"methods":{%s}}`,
		total, uniqueCalls, total, tsMin.Int64, tsMax.Int64, methods)
}

// buildTopCallsJSON returns calls with the most messages.
func buildTopCallsJSON(db *sql.DB, limit int, agent, state, src, dst, from, to string) string {
	where := "1=1"
	if agent != "" {
		where += fmt.Sprintf(" AND cs.agent='%s'", sqlQuote(agent))
	}
	if src != "" {
		where += fmt.Sprintf(" AND cs.src LIKE '%%%s%%'", sqlQuote(src))
	}
	if dst != "" {
		where += fmt.Sprintf(" AND cs.dst LIKE '%%%s%%'", sqlQuote(dst))
	}
	if from != "" {
		where += fmt.Sprintf(" AND cs.from_h LIKE '%%%s%%'", sqlQuote(from))
	}
	if to != "" {
		where += fmt.Sprintf(" AND cs.to_h LIKE '%%%s%%'", sqlQuote(to))
	}

	if limit <= 0 || limit > 100 {
		limit = 20
	}

	rows, err := db.Query(fmt.Sprintf(`
		SELECT cs.call_id, cs.first_ts_ms, cs.last_ts_ms, cs.from_h, cs.to_h,
			CASE WHEN cs.open=1 THEN 'active' ELSE 'ended' END AS state,
			GREATEST(cs.last_id - cs.invite_id, 1) AS messages
		FROM call_state cs WHERE %s AND cs.invite_id > 0
		ORDER BY (cs.last_id - cs.invite_id) DESC
		LIMIT %d`, where, limit))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var callID, fromH, toH, state string
		var firstTs, lastTs, messages int64
		rows.Scan(&callID, &firstTs, &lastTs, &fromH, &toH, &state, &messages)
		parts = append(parts, fmt.Sprintf(
			`{"call_id":"%s","messages":%d,"ts_first":%d,"ts_last":%d,"state":"%s","from":"%s","to":"%s"}`,
			jesc(callID), messages, firstTs, lastTs, state, jesc(fromH), jesc(toH)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildDailyJSON returns daily method breakdown.
func buildDailyJSON(db *sql.DB, limit int) string {
	if limit <= 0 || limit > 100 {
		limit = 14
	}
	rows, err := db.Query(fmt.Sprintf(`
		SELECT day, method, transport, cnt FROM report_daily
		ORDER BY day DESC, cnt DESC LIMIT %d`, limit*30))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var day, method, transport string
		var cnt int64
		rows.Scan(&day, &method, &transport, &cnt)
		parts = append(parts, fmt.Sprintf(
			`{"day":"%s","method":"%s","transport":"%s","count":%d}`,
			jesc(day), jesc(method), jesc(transport), cnt))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildSLAAgentsJSON returns SLA metrics per agent.
func buildSLAAgentsJSON(db *sql.DB, cfg *Config) string {
	cutoffMs := time.Now().Add(-time.Duration(cfg.KPIWindowMin) * time.Minute).UnixMilli()

	rows, err := db.Query(fmt.Sprintf(`
		SELECT agent,
			count(*) FILTER (WHERE invite_id > 0) AS invites,
			count(*) FILTER (WHERE answered=1) AS ok_2xx,
			count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400) AS errors
		FROM call_state WHERE first_ts_ms >= %d
		GROUP BY agent ORDER BY invites DESC`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var agent string
		var invites, ok2xx, errors int64
		rows.Scan(&agent, &invites, &ok2xx, &errors)
		asr := int64(0)
		if invites > 0 {
			asr = ok2xx * 100 / invites
		}
		errRate := int64(0)
		if invites > 0 {
			errRate = errors * 100 / invites
		}
		parts = append(parts, fmt.Sprintf(
			`{"agent":"%s","invites":%d,"ok_2xx":%d,"errors":%d,"asr":%d,"err_rate":%d}`,
			jesc(agent), invites, ok2xx, errors, asr, errRate))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildMessagesJSON returns filtered messages.
func buildMessagesJSON(db *sql.DB, limit int, callID, transport, agent, method, src, from, to, status, sinceMs, untilMs, state string) string {
	where := "1=1"
	if callID != "" {
		if strings.HasPrefix(callID, "/") {
			where += fmt.Sprintf(" AND call_id ~ '%s'", sqlQuote(callID[1:]))
		} else {
			where += fmt.Sprintf(" AND call_id='%s'", sqlQuote(callID))
		}
	}
	if transport != "" {
		where += fmt.Sprintf(" AND transport='%s'", sqlQuote(transport))
	}
	if agent != "" {
		where += fmt.Sprintf(" AND agent='%s'", sqlQuote(agent))
	}
	if method != "" {
		where += fmt.Sprintf(" AND method='%s'", sqlQuote(method))
	}
	if src != "" {
		if strings.HasPrefix(src, "/") {
			where += fmt.Sprintf(" AND (src ~ '%s' OR dst ~ '%s')", sqlQuote(src[1:]), sqlQuote(src[1:]))
		} else {
			where += fmt.Sprintf(" AND (src LIKE '%%%s%%' OR dst LIKE '%%%s%%')", sqlQuote(src), sqlQuote(src))
		}
	}
	if from != "" {
		where += likeOrRegex("from_h", from)
	}
	if to != "" {
		where += likeOrRegex("to_h", to)
	}
	if status != "" {
		// Support status ranges: "4" matches 4xx, "48" matches 480-489
		if len(status) < 3 {
			where += fmt.Sprintf(" AND CAST(status AS TEXT) LIKE '%s%%'", sqlQuote(status))
		} else {
			where += fmt.Sprintf(" AND status=%s", sqlQuote(status))
		}
	}
	if sinceMs != "" {
		where += fmt.Sprintf(" AND ts_ms >= %s", sqlQuote(sinceMs))
	}
	if untilMs != "" {
		where += fmt.Sprintf(" AND ts_ms <= %s", sqlQuote(untilMs))
	}

	if limit <= 0 || limit > 5000 {
		limit = 300
	}

	rows, err := db.Query(fmt.Sprintf(`
		SELECT id, ts_ms, src, dst, transport, proto, agent, kind, method, status,
			call_id, from_h, to_h, cseq, ruri, hep_node_id, hep_node, hep_cid, size, raw_b64
		FROM captures WHERE %s
		ORDER BY ts_ms DESC, id DESC LIMIT %d`, where, limit))
	if err != nil {
		return "[]"
	}
	defer rows.Close()

	var parts []string
	for rows.Next() {
		var id, tsMs int64
		var src, dst, transport, proto, agent, kind, method string
		var status, hepNodeID, size int
		var callID, fromH, toH, cseq, ruri, hepNode, hepCID, rawB64 string
		rows.Scan(&id, &tsMs, &src, &dst, &transport, &proto, &agent, &kind, &method, &status,
			&callID, &fromH, &toH, &cseq, &ruri, &hepNodeID, &hepNode, &hepCID, &size, &rawB64)
		parts = append(parts, fmt.Sprintf(
			`{"id":%d,"ts_ms":%d,"src":"%s","dst":"%s","transport":"%s","proto":"%s","agent":"%s","kind":"%s","method":"%s","status":%d,"call_id":"%s","from_h":"%s","to_h":"%s","cseq":"%s","ruri":"%s","hep_node_id":%d,"hep_node":"%s","hep_cid":"%s","size":%d,"raw_b64":"%s"}`,
			id, tsMs, jesc(src), jesc(dst), jesc(transport), jesc(proto), jesc(agent),
			jesc(kind), jesc(method), status, jesc(callID), jesc(fromH), jesc(toH),
			jesc(cseq), jesc(ruri), hepNodeID, jesc(hepNode), jesc(hepCID), size, jesc(rawB64)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildAnomaliesJSON detects anomaly conditions.
func buildAnomaliesJSON(db *sql.DB) string {
	cutoffMs := time.Now().Add(-5 * time.Minute).UnixMilli()
	var parts []string

	// Auth failures
	var authFails int64
	db.QueryRow(fmt.Sprintf("SELECT count(*) FROM captures WHERE ts_ms >= %d AND status IN (401,403)", cutoffMs)).Scan(&authFails)
	if authFails > 5 {
		parts = append(parts, fmt.Sprintf(`{"type":"auth_failures","severity":"warning","count":%d,"message":"Elevated auth failures in 5m"}`, authFails))
	}

	// 5xx errors
	var server5xx int64
	db.QueryRow(fmt.Sprintf("SELECT count(*) FROM captures WHERE ts_ms >= %d AND status >= 500", cutoffMs)).Scan(&server5xx)
	if server5xx > 0 {
		parts = append(parts, fmt.Sprintf(`{"type":"5xx_errors","severity":"critical","count":%d,"message":"Server errors detected in 5m"}`, server5xx))
	}

	// 486 busy spike
	var busy int64
	db.QueryRow(fmt.Sprintf("SELECT count(*) FROM captures WHERE ts_ms >= %d AND status = 486", cutoffMs)).Scan(&busy)
	if busy > 10 {
		parts = append(parts, fmt.Sprintf(`{"type":"busy_spike","severity":"warning","count":%d,"message":"Elevated 486 Busy responses in 5m"}`, busy))
	}

	return "[" + strings.Join(parts, ",") + "]"
}

// buildResponseCodesJSON returns SIP response code distribution.
func buildResponseCodesJSON(db *sql.DB) string {
	rows, err := db.Query(`
		SELECT status, count(*) AS cnt FROM (
			SELECT status FROM captures WHERE status > 0 ORDER BY id DESC LIMIT 50000
		) sub GROUP BY status ORDER BY cnt DESC LIMIT 30`)
	if err != nil {
		return "[]"
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var status int
		var cnt int64
		rows.Scan(&status, &cnt)
		reason := sipReasonPhrase(status)
		parts = append(parts, fmt.Sprintf(`{"status":%d,"reason":"%s","count":%d}`, status, jesc(reason), cnt))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func sipReasonPhrase(code int) string {
	switch code {
	case 100: return "Trying"
	case 180: return "Ringing"
	case 183: return "Session Progress"
	case 200: return "OK"
	case 302: return "Moved Temporarily"
	case 400: return "Bad Request"
	case 401: return "Unauthorized"
	case 403: return "Forbidden"
	case 404: return "Not Found"
	case 405: return "Method Not Allowed"
	case 407: return "Proxy Auth Required"
	case 408: return "Request Timeout"
	case 480: return "Temporarily Unavailable"
	case 481: return "Call Does Not Exist"
	case 486: return "Busy Here"
	case 487: return "Request Terminated"
	case 488: return "Not Acceptable Here"
	case 500: return "Server Internal Error"
	case 502: return "Bad Gateway"
	case 503: return "Service Unavailable"
	case 504: return "Server Timeout"
	default: return ""
	}
}

// buildCPSJSON returns calls-per-minute over a time window.
func buildCPSJSON(db *sql.DB, minutes int) string {
	if minutes <= 0 || minutes > 1440 {
		minutes = 60
	}
	cutoffMs := time.Now().Add(-time.Duration(minutes) * time.Minute).UnixMilli()
	// Use report_daily for historical, call_state for recent CPS
	rows, err := db.Query(fmt.Sprintf(`
		SELECT (first_ts_ms / 60000) AS bucket,
			count(*) AS total,
			count(*) FILTER (WHERE invite_id > 0) AS invites
		FROM call_state WHERE first_ts_ms >= %d
		GROUP BY bucket ORDER BY bucket`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var bucket, total, invites int64
		rows.Scan(&bucket, &total, &invites)
		parts = append(parts, fmt.Sprintf(`{"minute":%d,"total":%d,"invites":%d}`, bucket, total, invites))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildSLADestJSON returns SLA metrics per destination IP with ASR and ACD.
func buildSLADestJSON(db *sql.DB, cfg *Config) string {
	cutoffMs := time.Now().Add(-5 * time.Minute).UnixMilli()
	rows, err := db.Query(fmt.Sprintf(`
		SELECT split_part(dst,':',1) AS dest,
			count(*) FILTER (WHERE invite_id > 0) AS invites,
			count(*) FILTER (WHERE answered=1) AS ok_2xx,
			count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400) AS errors,
			COALESCE(round(avg((last_ts_ms - answer_ts_ms)/1000.0) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms > 0 AND last_ts_ms > answer_ts_ms)),0) AS acd
		FROM call_state WHERE first_ts_ms >= %d
		GROUP BY dest HAVING count(*) FILTER (WHERE invite_id > 0) > 0
		ORDER BY invites DESC LIMIT 50`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var dest string
		var invites, ok2xx, errors, acd int64
		rows.Scan(&dest, &invites, &ok2xx, &errors, &acd)
		asr := int64(0)
		if invites > 0 { asr = ok2xx * 100 / invites; if asr > 100 { asr = 100 } }
		parts = append(parts, fmt.Sprintf(
			`{"dst":"%s","invites":%d,"ok_2xx":%d,"errors":%d,"asr":%d,"acd":%d}`,
			jesc(dest), invites, ok2xx, errors, asr, acd))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildSLASrcJSON returns SLA metrics per source IP with ASR and ACD.
func buildSLASrcJSON(db *sql.DB, cfg *Config) string {
	cutoffMs := time.Now().Add(-5 * time.Minute).UnixMilli()
	rows, err := db.Query(fmt.Sprintf(`
		SELECT split_part(src,':',1) AS source,
			count(*) FILTER (WHERE invite_id > 0) AS invites,
			count(*) FILTER (WHERE answered=1) AS ok_2xx,
			count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400) AS errors,
			COALESCE(round(avg((last_ts_ms - answer_ts_ms)/1000.0) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms > 0 AND last_ts_ms > answer_ts_ms)),0) AS acd
		FROM call_state WHERE first_ts_ms >= %d
		GROUP BY source HAVING count(*) FILTER (WHERE invite_id > 0) > 0
		ORDER BY invites DESC LIMIT 50`, cutoffMs))
	if err != nil {
		return "[]"
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var source string
		var invites, ok2xx, errors, acd int64
		rows.Scan(&source, &invites, &ok2xx, &errors, &acd)
		asr := int64(0)
		if invites > 0 { asr = ok2xx * 100 / invites; if asr > 100 { asr = 100 } }
		parts = append(parts, fmt.Sprintf(
			`{"src":"%s","invites":%d,"ok_2xx":%d,"errors":%d,"asr":%d,"acd":%d}`,
			jesc(source), invites, ok2xx, errors, asr, acd))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// buildCarrierScoreJSON returns detailed per-carrier metrics with breakdown.
func buildCarrierScoreJSON(db *sql.DB, ip string) string {
	if ip == "" {
		return `{"error":"ip required"}`
	}
	cutoffMs := time.Now().Add(-60 * time.Minute).UnixMilli()

	// Overall stats
	var invites, ok2xx, errors, acd int64
	db.QueryRow(fmt.Sprintf(`SELECT
		count(*) FILTER (WHERE invite_id > 0),
		count(*) FILTER (WHERE answered=1),
		count(*) FILTER (WHERE answered=0 AND open=0 AND last_status >= 400),
		COALESCE(round(avg((last_ts_ms-answer_ts_ms)/1000.0) FILTER (WHERE answered=1 AND open=0 AND answer_ts_ms>0 AND last_ts_ms>answer_ts_ms)),0)
		FROM call_state WHERE first_ts_ms >= %d AND (split_part(dst,':',1)='%s' OR split_part(src,':',1)='%s')`,
		cutoffMs, sqlQuote(ip), sqlQuote(ip))).Scan(&invites, &ok2xx, &errors, &acd)

	asr := int64(0)
	if invites > 0 {
		asr = ok2xx * 100 / invites
		if asr > 100 {
			asr = 100
		}
	}

	// Error code breakdown
	rows, err := db.Query(fmt.Sprintf(`SELECT last_status, count(*) FROM call_state
		WHERE first_ts_ms >= %d AND (split_part(dst,':',1)='%s' OR split_part(src,':',1)='%s')
		AND answered=0 AND open=0 AND last_status >= 400
		GROUP BY last_status ORDER BY count(*) DESC LIMIT 10`,
		cutoffMs, sqlQuote(ip), sqlQuote(ip)))
	errCodes := ""
	if err == nil {
		defer rows.Close()
		var eParts []string
		for rows.Next() {
			var code int
			var cnt int64
			rows.Scan(&code, &cnt)
			eParts = append(eParts, fmt.Sprintf(`"%d":%d`, code, cnt))
		}
		errCodes = strings.Join(eParts, ",")
	}

	// Per-minute trend (last 60 min)
	trows, err := db.Query(fmt.Sprintf(`SELECT (first_ts_ms/60000) AS bucket,
		count(*) FILTER (WHERE invite_id > 0) AS inv,
		count(*) FILTER (WHERE answered=1) AS ans
		FROM call_state WHERE first_ts_ms >= %d AND (split_part(dst,':',1)='%s' OR split_part(src,':',1)='%s')
		GROUP BY bucket ORDER BY bucket`,
		cutoffMs, sqlQuote(ip), sqlQuote(ip)))
	trend := ""
	if err == nil {
		defer trows.Close()
		var tParts []string
		for trows.Next() {
			var bucket, inv, ans int64
			trows.Scan(&bucket, &inv, &ans)
			tParts = append(tParts, fmt.Sprintf(`{"m":%d,"inv":%d,"ans":%d}`, bucket, inv, ans))
		}
		trend = strings.Join(tParts, ",")
	}

	return fmt.Sprintf(`{"ip":"%s","invites":%d,"ok_2xx":%d,"errors":%d,"asr":%d,"acd":%d,"error_codes":{%s},"trend":[%s]}`,
		jesc(ip), invites, ok2xx, errors, asr, acd, errCodes, trend)
}

// buildQoSJSON returns QoS metrics for a specific call.
func buildQoSJSON(db *sql.DB, callID string) string {
	row := db.QueryRow("SELECT qos_worst_mos, qos_max_jitter_ms, qos_max_loss_pct, qos_rtcp_count, qos_codec FROM call_state WHERE call_id=$1 LIMIT 1", callID)
	var mos, jitter, loss, rtcpCount int
	var codec string
	if err := row.Scan(&mos, &jitter, &loss, &rtcpCount, &codec); err != nil || rtcpCount == 0 {
		return "[]"
	}
	return fmt.Sprintf(`[{"mos_x10":%d,"jitter_ms":%d,"loss_pct":%d,"r_factor":%d,"codec":"%s","samples":%d}]`,
		mos, jitter, loss, rFactorFromJitterLoss(float64(jitter), float64(loss)), jesc(codec), rtcpCount)
}
