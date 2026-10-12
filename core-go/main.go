package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const Version = "0.4.0"

// Config holds all environment-based configuration.
type Config struct {
	SIPHost  string
	SIPPort  int
	HEPPort  int
	APIPort  int
	HEPTCP  bool
	HEPTCPPort int
	HEPTLS  bool
	HEPTLSPort int
	HEPTLSCert string
	HEPTLSKey  string

	DBDriver string
	DBDSN    string

	APIKey      string
	HEPPassword string
	HEPAllow    []string

	EchoAll     bool
	ProbeEnabled bool
	ProbeAllowPrivate bool

	RetentionDays int
	RateLimit     int
	TrustedProxy  string

	StaticDir string

	ConcurrentCallMaxAge int // seconds
	RingingMaxAge        int // seconds
	KPIWindowMin         int

	ASRExcludeCodes []int

	FederationTarget string
}

func loadConfig() *Config {
	c := &Config{
		SIPHost:    env("ZAMAN_SIP_HOST", "0.0.0.0"),
		SIPPort:    envInt("ZAMAN_SIP_PORT", 5060),
		HEPPort:    envInt("ZAMAN_HEP_PORT", 9060),
		APIPort:    envInt("ZAMAN_API_PORT", 9090),
		HEPTCPPort: envInt("ZAMAN_HEP_TCP_PORT", 9062),
		HEPTLSPort: envInt("ZAMAN_HEP_TLS_PORT", 9061),
		HEPTLSCert: env("ZAMAN_HEP_TLS_CERT", ""),
		HEPTLSKey:  env("ZAMAN_HEP_TLS_KEY", ""),
		DBDriver:   env("ZAMAN_DB_DRIVER", "postgres"),
		DBDSN:      env("ZAMAN_DB_DSN", "host=localhost dbname=zaman sslmode=disable"),
		APIKey:     env("ZAMAN_API_KEY", ""),
		HEPPassword: env("ZAMAN_HEP_PASSWORD", ""),
		StaticDir:  env("ZAMAN_STATIC_DIR", "web/static"),
		TrustedProxy: env("ZAMAN_TRUSTED_PROXY", ""),
		RetentionDays: envInt("ZAMAN_DB_RETENTION_DAYS", 14),
		RateLimit:     envInt("ZAMAN_RATE_LIMIT", 100),
		ConcurrentCallMaxAge: envInt("ZAMAN_CONCURRENT_CALL_MAX_AGE_SEC", 7200),
		RingingMaxAge:        envInt("ZAMAN_CONCURRENT_RINGING_MAX_AGE_SEC", 300),
		KPIWindowMin:         envInt("ZAMAN_KPI_WINDOW_MIN", 1440),
	}

	c.HEPTCP = env("ZAMAN_HEP_TCP", "0") == "1"
	c.HEPTLS = env("ZAMAN_HEP_TLS", "0") == "1"
	c.EchoAll = env("ZAMAN_ECHO_ALL", "0") == "1"
	c.ProbeEnabled = env("ZAMAN_PROBE", "0") == "1"
	c.ProbeAllowPrivate = env("ZAMAN_PROBE_ALLOW_PRIVATE", "0") == "1"
	c.FederationTarget = env("ZAMAN_FEDERATION_TARGET", "")

	// Parse HEP allow list
	if allow := env("ZAMAN_HEP_ALLOW", ""); allow != "" {
		for _, s := range strings.Split(allow, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				c.HEPAllow = append(c.HEPAllow, s)
			}
		}
	}

	// Parse ASR exclude codes
	c.ASRExcludeCodes = []int{403, 503}
	if codes := env("ZAMAN_ASR_EXCLUDE_STATUS_CODES", ""); codes != "" {
		c.ASRExcludeCodes = nil
		for _, s := range strings.Split(codes, ",") {
			if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
				c.ASRExcludeCodes = append(c.ASRExcludeCodes, v)
			}
		}
	}

	// CLI args override: [sip_port] [hep_port] [api_port]
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil {
			c.SIPPort = v
		}
	}
	if len(os.Args) > 2 {
		if v, err := strconv.Atoi(os.Args[2]); err == nil {
			c.HEPPort = v
		}
	}
	if len(os.Args) > 3 {
		if v, err := strconv.Atoi(os.Args[3]); err == nil {
			c.APIPort = v
		}
	}

	return c
}

// Metrics holds atomic counters for the system.
type Metrics struct {
	mu          sync.Mutex
	StartTime   time.Time
	MsgsTotal   int64
	Requests    int64
	Responses   int64
	Echoes      int64
	DBOk        int64
	DBErr       int64
	DBDrop      int64
	HEPTotal    int64
	HEPUDP      int64
	HEPTCP      int64
	HEPTLS      int64
	HEPErr      int64
	HEPAuthFail int64
	HEPDeny     int64
	HEPSIP      int64
	HEPRTCP     int64
	HEPRTP      int64
	HEPRTCPXR   int64
	HEPOther    int64
	ParseErr    int64
	ProbesOk    int64
	ProbesFail  int64
	ProbeRTT    int64
	Methods     map[string]int64
	Status2xx   int64
	Status4xx5xx int64
}

func newMetrics() *Metrics {
	return &Metrics{
		StartTime: time.Now(),
		Methods:   make(map[string]int64),
	}
}

func (m *Metrics) Inc(field *int64, delta int64) {
	m.mu.Lock()
	*field += delta
	m.mu.Unlock()
}

func (m *Metrics) BumpMethod(method string) {
	m.mu.Lock()
	m.Methods[method]++
	m.mu.Unlock()
}

// Ring is a circular buffer of recent capture records (JSON strings).
const RingSize = 512

type Ring struct {
	mu    sync.Mutex
	buf   [RingSize]string
	idx   int
}

func (r *Ring) Push(rec string) {
	r.mu.Lock()
	r.buf[r.idx%RingSize] = rec
	r.idx++
	r.mu.Unlock()
}

func (r *Ring) Recent(limit int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.idx
	if n > RingSize {
		n = RingSize
	}
	if limit > n {
		limit = n
	}
	out := make([]string, limit)
	for i := 0; i < limit; i++ {
		out[i] = r.buf[(r.idx-1-i+RingSize*2)%RingSize]
	}
	return out
}

// Auth helpers
func constantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func apiAuthorized(cfg *Config, r interface{ Header() string }) bool {
	if cfg.APIKey == "" {
		return true
	}
	// Checked via HTTP handler
	return false
}

// Env helpers
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// JSON escape for untrusted strings
func jesc(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, c)
			} else {
				b.WriteRune(c)
			}
		}
	}
	return b.String()
}

// Day key for daily rollup (unix day number as string)
func dayKey(tsMs int64) string {
	return strconv.FormatInt(tsMs/86400000, 10)
}

// Hex encoding helper
func randomHex(n int) string {
	b := make([]byte, n)
	// Use crypto/rand in real usage, but for metrics keys this is fine
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i * 8))
	}
	return hex.EncodeToString(b)
}

func hmacSHA256(key, data string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func main() {
	cfg := loadConfig()

	log.Printf("zaman-core v%s starting", Version)
	log.Printf("  SIP  %s:%d", cfg.SIPHost, cfg.SIPPort)
	log.Printf("  HEP  %s:%d", cfg.SIPHost, cfg.HEPPort)
	log.Printf("  API  0.0.0.0:%d", cfg.APIPort)
	log.Printf("  DB   %s", cfg.DBDriver)

	// Initialize database
	db, err := dbInit(cfg)
	if err != nil {
		log.Fatalf("db init: %v", err)
	}
	defer db.Close()

	metrics := newMetrics()
	ring := &Ring{}
	cache := NewCache()

	// DB write channel
	dbCh := make(chan string, 4096)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
	}()

	var wg sync.WaitGroup

	// DB writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		dbWriter(ctx, db, cfg, metrics, dbCh)
	}()

	// Cache worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		cacheWorker(ctx, db, cfg, metrics, cache)
	}()

	// SIP worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		sipWorker(ctx, cfg, metrics, ring, dbCh)
	}()

	// HEP UDP worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		hepUDPWorker(ctx, cfg, metrics, ring, dbCh)
	}()

	// HEP TCP worker (optional)
	if cfg.HEPTCPPort > 0 && cfg.HEPTCPPort != cfg.HEPPort {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hepTCPWorker(ctx, cfg, metrics, ring, dbCh)
		}()
	}

	// HEP TLS worker (optional)
	if cfg.HEPTLS && cfg.HEPTLSCert != "" && cfg.HEPTLSKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hepTLSWorker(ctx, cfg, metrics, ring, dbCh)
		}()
	}

	// HTTP API worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		apiWorker(ctx, db, cfg, metrics, ring, cache, dbCh)
	}()

	// Alert webhook worker
	wg.Add(1)
	go func() {
		defer wg.Done()
		alertWorker(ctx, db, cfg)
	}()

	log.Printf("zaman-core ready")
	wg.Wait()
	log.Printf("zaman-core stopped")
}
