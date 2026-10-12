package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// dbInit opens PostgreSQL and creates schema with daily partitioning.
func dbInit(cfg *Config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.DBDSN)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping: %w", err)
	}

	// Create partitioned captures table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS captures (
			id          BIGSERIAL,
			ts_ms       BIGINT NOT NULL,
			src         TEXT DEFAULT '',
			dst         TEXT DEFAULT '',
			transport   TEXT DEFAULT '',
			proto       TEXT DEFAULT '',
			agent       TEXT DEFAULT '',
			kind        TEXT DEFAULT '',
			method      TEXT DEFAULT '',
			status      INTEGER DEFAULT 0,
			call_id     TEXT DEFAULT '',
			from_h      TEXT DEFAULT '',
			to_h        TEXT DEFAULT '',
			cseq        TEXT DEFAULT '',
			ruri        TEXT DEFAULT '',
			hep_node_id INTEGER DEFAULT 0,
			hep_node    TEXT DEFAULT '',
			hep_cid     TEXT DEFAULT '',
			size        INTEGER DEFAULT 0,
			raw_b64     TEXT DEFAULT '',
			record_json TEXT DEFAULT ''
		) PARTITION BY RANGE (ts_ms)
	`)
	if err != nil {
		// Table might exist as non-partitioned from old Makori core
		// Check if it already exists
		var exists bool
		db.QueryRow("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='captures')").Scan(&exists)
		if exists {
			log.Println("db: captures table exists (may be non-partitioned from prior install)")
		} else {
			return nil, fmt.Errorf("create captures: %w", err)
		}
	}

	// Check if table is partitioned before trying to create partitions
	var isPartitioned bool
	db.QueryRow("SELECT EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid='captures'::regclass)").Scan(&isPartitioned)
	if isPartitioned {
		ensurePartitions(db, time.Now())
	} else {
		log.Println("db: captures is not partitioned (legacy table) — skipping partition creation")
	}

	// call_state table (not partitioned — small, different access pattern)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS call_state (
			call_id       TEXT NOT NULL,
			agent         TEXT NOT NULL DEFAULT '',
			first_ts_ms   BIGINT NOT NULL,
			answer_ts_ms  BIGINT NOT NULL DEFAULT 0,
			last_ts_ms    BIGINT NOT NULL,
			last_id       BIGINT NOT NULL DEFAULT 0,
			invite_id     BIGINT NOT NULL DEFAULT 0,
			last_method   TEXT DEFAULT '',
			last_status   INTEGER DEFAULT 0,
			answered      INTEGER DEFAULT 0,
			open          INTEGER DEFAULT 1,
			src           TEXT DEFAULT '',
			dst           TEXT DEFAULT '',
			from_h        TEXT DEFAULT '',
			to_h          TEXT DEFAULT '',
			record_json   TEXT DEFAULT '',
			qos_worst_mos    INTEGER NOT NULL DEFAULT 0,
			qos_max_jitter_ms INTEGER NOT NULL DEFAULT 0,
			qos_max_loss_pct  INTEGER NOT NULL DEFAULT 0,
			qos_rtcp_count    INTEGER NOT NULL DEFAULT 0,
			qos_codec         TEXT NOT NULL DEFAULT '',
			PRIMARY KEY(call_id, agent)
		)
	`)
	if err != nil {
		log.Printf("db: call_state create (may exist): %v", err)
	}

	// call_state indexes
	for _, idx := range []string{
		"CREATE INDEX IF NOT EXISTS idx_call_state_open_agent_last ON call_state (open, agent, last_ts_ms DESC)",
		"CREATE INDEX IF NOT EXISTS idx_call_state_first ON call_state (first_ts_ms DESC)",
		"CREATE INDEX IF NOT EXISTS idx_call_state_first_answered ON call_state (first_ts_ms DESC, answered)",
		"CREATE INDEX IF NOT EXISTS idx_call_state_first_open_status ON call_state (first_ts_ms DESC, open, last_status)",
		"CREATE INDEX IF NOT EXISTS idx_call_state_agent_last ON call_state (agent, last_ts_ms DESC)",
	} {
		db.Exec(idx)
	}

	// report_daily table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS report_daily (
			day       TEXT NOT NULL,
			method    TEXT NOT NULL,
			transport TEXT NOT NULL,
			cnt       INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(day, method, transport)
		)
	`)
	if err != nil {
		log.Printf("db: report_daily create (may exist): %v", err)
	}

	log.Println("db: schema ready")
	return db, nil
}

// ensurePartitions creates daily partitions for the given time and the next day.
func ensurePartitions(db *sql.DB, now time.Time) {
	for i := 0; i < 3; i++ {
		d := now.AddDate(0, 0, i)
		createDayPartition(db, d)
	}
}

func createDayPartition(db *sql.DB, day time.Time) {
	name := fmt.Sprintf("captures_%s", day.Format("20060102"))
	startMs := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC).UnixMilli()
	endMs := startMs + 86400000

	sql := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s PARTITION OF captures FOR VALUES FROM (%d) TO (%d)`,
		name, startMs, endMs)
	_, err := db.Exec(sql)
	if err != nil {
		// Ignore "already exists" errors
		if !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "overlaps") {
			log.Printf("db: partition %s: %v", name, err)
		}
	} else {
		// Create indexes on new partition
		for _, idx := range []string{
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_call_id ON %s (call_id)", name, name),
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_agent_ts ON %s (agent, ts_ms DESC)", name, name),
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_ts ON %s (ts_ms DESC)", name, name),
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s_method_kind_ts ON %s (method, kind, ts_ms DESC, call_id)", name, name),
		} {
			db.Exec(idx)
		}
	}
}

// dropOldPartitions drops partitions older than retention days.
func dropOldPartitions(db *sql.DB, retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	// Scan for old partitions
	rows, err := db.Query(`
		SELECT tablename FROM pg_tables
		WHERE schemaname='public' AND tablename LIKE 'captures_%'
		ORDER BY tablename`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		rows.Scan(&name)
		// Parse date from name: captures_20261009
		if len(name) < 18 {
			continue
		}
		dateStr := name[9:] // "20261009"
		t, err := time.Parse("20060102", dateStr)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			log.Printf("db: dropping old partition %s", name)
			db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", name))
		}
	}
}

// CaptureRecord is the parsed JSON record for DB insertion.
type CaptureRecord struct {
	TsMs          int64  `json:"ts_ms"`
	Src           string `json:"src"`
	Dst           string `json:"dst"`
	Transport     string `json:"transport"`
	Proto         string `json:"proto"`
	Agent         string `json:"agent"`
	Kind          string `json:"kind"`
	Method        string `json:"method"`
	Status        int    `json:"status"`
	CallID        string `json:"call_id"`
	From          string `json:"from"`
	To            string `json:"to"`
	CSeq          string `json:"cseq"`
	RURI          string `json:"ruri"`
	HEPNodeID     int    `json:"hep_node_id"`
	HEPNode       string `json:"hep_node"`
	HEPCID        string `json:"hep_cid"`
	Size          int    `json:"size"`
	RawB64        string `json:"raw_b64"`
}

// dbWriter consumes records from the channel and batch-inserts into PostgreSQL.
func dbWriter(ctx context.Context, db *sql.DB, cfg *Config, metrics *Metrics, ch <-chan string) {
	log.Println("db: writer started")

	const batchSize = 100
	const flushInterval = 200 * time.Millisecond

	batch := make([]string, 0, batchSize)
	flushTick := time.NewTicker(flushInterval)
	defer flushTick.Stop()

	partitionTick := time.NewTicker(1 * time.Hour)
	defer partitionTick.Stop()

	retentionTick := time.NewTicker(15 * time.Minute)
	defer retentionTick.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		recs := make([]CaptureRecord, 0, len(batch))
		for _, recJSON := range batch {
			var rec CaptureRecord
			if err := json.Unmarshal([]byte(recJSON), &rec); err != nil {
				metrics.Inc(&metrics.DBErr, 1)
				continue
			}
			recs = append(recs, rec)
		}
		if err := dbBatchInsert(db, recs, batch, metrics); err != nil {
			metrics.Inc(&metrics.DBErr, int64(len(recs)))
			if metrics.DBErr%100 < int64(len(recs)) {
				log.Printf("db: batch insert error: %v", err)
			}
		} else {
			metrics.Inc(&metrics.DBOk, int64(len(recs)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-partitionTick.C:
			ensurePartitions(db, time.Now())
		case <-retentionTick.C:
			dropOldPartitions(db, cfg.RetentionDays)
			if cfg.RetentionDays > 0 {
				cutoffMs := time.Now().Add(-time.Duration(cfg.RetentionDays) * 24 * time.Hour).UnixMilli()
				db.Exec("DELETE FROM call_state WHERE last_ts_ms < $1", cutoffMs)
			}
		case <-flushTick.C:
			flush()
		case recJSON, ok := <-ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, recJSON)
			if len(batch) >= batchSize {
				flush()
			}
		}
	}
}

// dbBatchInsert inserts multiple records in a single transaction.
func dbBatchInsert(db *sql.DB, recs []CaptureRecord, rawJSONs []string, metrics *Metrics) error {
	if len(recs) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO captures (ts_ms, src, dst, transport, proto, agent, kind, method, status,
			call_id, from_h, to_h, cseq, ruri, hep_node_id, hep_node, hep_cid, size, raw_b64, record_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		RETURNING id`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Prepare call_state upsert ($7=isClosed 0/1, $8=isAnswered 0/1, $9=isInviteReq 0/1)
	csStmt, err := tx.Prepare(`
		INSERT INTO call_state (call_id, agent, first_ts_ms, last_ts_ms, last_id, last_method, last_status,
			open, answered, invite_id, src, dst, from_h, to_h, record_json, answer_ts_ms)
		VALUES ($1, $2, $3::bigint, $3::bigint, $4::bigint, $5, $6::int,
			CASE WHEN $7::int = 1 THEN 0 ELSE 1 END,
			$8::int,
			CASE WHEN $9::int = 1 THEN $4::bigint ELSE 0::bigint END,
			$10, $11, $12, $13, $14,
			CASE WHEN $8::int = 1 THEN $3::bigint ELSE 0::bigint END)
		ON CONFLICT (call_id, agent) DO UPDATE SET
			last_ts_ms = GREATEST(call_state.last_ts_ms, $3::bigint),
			last_id = $4::bigint,
			last_method = $5,
			last_status = $6::int,
			open = CASE WHEN $7::int = 1 THEN 0 ELSE call_state.open END,
			answered = CASE WHEN $8::int = 1 THEN 1 ELSE call_state.answered END,
			invite_id = CASE WHEN $9::int = 1 AND call_state.invite_id = 0 THEN $4::bigint ELSE call_state.invite_id END,
			answer_ts_ms = CASE WHEN $8::int = 1 AND call_state.answer_ts_ms = 0 THEN $3::bigint ELSE call_state.answer_ts_ms END,
			record_json = $14`)
	if err != nil {
		return err
	}
	defer csStmt.Close()

	// Daily rollup accumulator
	dailyCounts := make(map[string]int)

	for i, rec := range recs {
		var id int64
		rawJSON := ""
		if i < len(rawJSONs) {
			rawJSON = rawJSONs[i]
		}
		err := stmt.QueryRow(
			rec.TsMs, rec.Src, rec.Dst, rec.Transport, rec.Proto, rec.Agent,
			rec.Kind, rec.Method, rec.Status, rec.CallID,
			rec.From, rec.To, rec.CSeq, rec.RURI,
			rec.HEPNodeID, rec.HEPNode, rec.HEPCID, rec.Size, rec.RawB64, rawJSON,
		).Scan(&id)
		if err != nil {
			continue // skip this record, don't fail the batch
		}

		// Update call_state
		if rec.CallID != "" {
			baseMethod := rec.Method
			if parts := strings.SplitN(baseMethod, " ", 2); len(parts) == 2 {
				baseMethod = parts[1]
			}
			isInviteReq := baseMethod == "INVITE" && rec.Kind == "request"
			isInviteResp := baseMethod == "INVITE" && rec.Kind == "response"
			is2xx := rec.Status >= 200 && rec.Status < 300
			isBye := baseMethod == "BYE"
			isCancel := baseMethod == "CANCEL"

			isClosed := 0
			if isBye || isCancel {
				isClosed = 1
			}
			isAnswered := 0
			if isInviteResp && is2xx {
				isAnswered = 1
			}
			isInvReq := 0
			if isInviteReq {
				isInvReq = 1
			}
			csStmt.Exec(rec.CallID, rec.Agent, rec.TsMs, id, rec.Method, rec.Status,
				isClosed, isAnswered, isInvReq,
				rec.Src, rec.Dst, rec.From, rec.To, rec.Method+" record")
		}

		// Accumulate daily rollup
		if rec.Method != "" {
			key := dayKey(rec.TsMs) + "|" + rec.Method + "|" + rec.Transport
			dailyCounts[key]++
		}
	}

	// Batch daily rollup
	for key, cnt := range dailyCounts {
		parts := strings.SplitN(key, "|", 3)
		if len(parts) == 3 {
			tx.Exec(`INSERT INTO report_daily (day, method, transport, cnt)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (day, method, transport)
				DO UPDATE SET cnt = report_daily.cnt + $4`,
				parts[0], parts[1], parts[2], cnt)
		}
	}

	return tx.Commit()
}


// SQL helpers for report queries
func sqlQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func activeCallWhere(cfg *Config) string {
	now := time.Now().UnixMilli()
	answeredCutoff := now - int64(cfg.ConcurrentCallMaxAge)*1000
	ringingCutoff := now - int64(cfg.RingingMaxAge)*1000
	return fmt.Sprintf(`(open=1 AND ((answered=1 AND last_ts_ms >= %d) OR (answered=0 AND last_ts_ms >= %d)))`,
		answeredCutoff, ringingCutoff)
}
