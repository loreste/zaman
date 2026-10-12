package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type AlertConfig struct {
	Webhooks   []string          `json:"webhooks"`
	Thresholds map[string]int    `json:"thresholds"`
}

func loadAlertConfig(dataDir string) AlertConfig {
	cfg := AlertConfig{
		Thresholds: map[string]int{"asr_min": 70, "err_rate_max": 10},
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "zaman-alert-config.json"))
	if err != nil {
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

// alertWorker checks anomalies every 60 seconds and fires webhooks.
func alertWorker(ctx context.Context, db *sql.DB, cfg *Config) {
	dataDir := env("ZAMAN_DATA_DIR", "data")
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			acfg := loadAlertConfig(dataDir)
			if len(acfg.Webhooks) == 0 {
				continue
			}

			anomalies := buildAnomaliesJSON(db)
			if anomalies == "[]" {
				continue
			}

			// Check ASR threshold
			rt := buildRealtimeJSON(db, cfg, 5, "")
			var rtData map[string]interface{}
			json.Unmarshal([]byte(rt), &rtData)

			var alerts []map[string]string

			// Parse anomalies
			var anomalyList []map[string]interface{}
			json.Unmarshal([]byte(anomalies), &anomalyList)
			for _, a := range anomalyList {
				if sev, _ := a["severity"].(string); sev == "critical" {
					alerts = append(alerts, map[string]string{
						"type":    fmt.Sprintf("%v", a["type"]),
						"message": fmt.Sprintf("%v", a["message"]),
						"count":   fmt.Sprintf("%v", a["count"]),
					})
				}
			}

			if len(alerts) == 0 {
				continue
			}

			// Build webhook payload
			payload := map[string]interface{}{
				"source":    "zaman",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"alerts":    alerts,
			}
			body, _ := json.Marshal(payload)

			// Fire to all webhooks
			for _, url := range acfg.Webhooks {
				go func(u string) {
					client := &http.Client{Timeout: 10 * time.Second}
					resp, err := client.Post(u, "application/json", bytes.NewReader(body))
					if err != nil {
						log.Printf("alert: webhook %s failed: %v", u, err)
						return
					}
					resp.Body.Close()
				}(url)
			}
		}
	}
}
