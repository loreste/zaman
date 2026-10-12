package main

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"
)

// Cache holds pre-computed JSON responses, refreshed every 3 seconds.
type Cache struct {
	mu   sync.RWMutex
	data map[string]string
}

func NewCache() *Cache {
	return &Cache{data: make(map[string]string)}
}

func (c *Cache) Set(key, value string) {
	c.mu.Lock()
	c.data[key] = value
	c.mu.Unlock()
}

func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	v, ok := c.data[key]
	c.mu.RUnlock()
	return v, ok
}

// cacheWorker refreshes cache every 3 seconds.
func cacheWorker(ctx context.Context, db *sql.DB, cfg *Config, metrics *Metrics, cache *Cache) {
	log.Println("cache: worker started")
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()

	// Initial refresh
	refreshCache(db, cfg, metrics, cache)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			refreshCache(db, cfg, metrics, cache)
		}
	}
}

func refreshCache(db *sql.DB, cfg *Config, metrics *Metrics, cache *Cache) {
	// Realtime (1-min window)
	if j := buildRealtimeJSON(db, cfg, 1, ""); j != "" {
		cache.Set("realtime", j)
	}

	// Node health
	if j := buildNodesJSON(db, cfg); j != "" {
		cache.Set("nodes", j)
	}

	// Active calls (no filters)
	if j := buildActiveCallsJSON(db, cfg, 50, "", "", "", "", "", ""); j != "" {
		cache.Set("calls", j)
	}

	// Top talkers
	if j := buildTopTalkersJSON(db, 20); j != "" {
		cache.Set("top_talkers", j)
	}

	// Agents
	if j := buildAgentsJSON(db); j != "" {
		cache.Set("agents", j)
	}

	// SLA by agent
	if j := buildSLAAgentsJSON(db, cfg); j != "" {
		cache.Set("sla_agents", j)
	}
}
