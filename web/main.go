package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	coreURL := env("ZAMAN_CORE", "http://127.0.0.1:9090")
	addr := ":" + env("ZAMAN_WEB_PORT", "3000")
	dataDir := env("ZAMAN_DATA_DIR", "data")
	authOn := env("ZAMAN_AUTH", "") != "0"
	apiKey := env("ZAMAN_API_KEY", "")

	apiKeyGlobal = apiKey

	core, err := url.Parse(coreURL)
	if err != nil {
		log.Fatalf("bad ZAMAN_CORE url: %v", err)
	}

	tokenSecret := loadOrCreateSecret(dataDir)

	if authOn {
		initAdmin(dataDir, tokenSecret)
	}

	// Reverse proxy to core API
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = core.Scheme
			r.URL.Host = core.Host
			r.Host = core.Host
			if apiKey != "" {
				r.Header.Set("X-API-Key", apiKey)
			}
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
		},
	}

	mux := http.NewServeMux()

	// Favicon
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fmt.Fprint(w, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#a78bfa"/><stop offset="100%" stop-color="#6d28d9"/></linearGradient></defs><rect width="32" height="32" rx="7" fill="url(#g)"/><text x="16" y="23" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="900" font-size="20" fill="#fff">Z</text></svg>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/favicon.svg", http.StatusFound)
	})

	// Health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})

	// Auth routes
	if authOn {
		rl := newRateLimiter()

		mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				// Already logged in?
				if u := getUser(r, tokenSecret); u != nil {
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}
				serveLoginPage(w, "")
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.ParseForm()
			ip := clientIP(r)
			if !rl.allow(ip) {
				serveLoginPage(w, "Too many login attempts. Please wait 60 seconds.")
				return
			}
			username := r.FormValue("username")
			password := r.FormValue("password")
			token := doLogin(dataDir, tokenSecret, username, password)
			if token == "" {
				rl.record(ip)
				serveLoginPage(w, "Invalid username or password.")
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "zaman_sid",
				Value:    token,
				Path:     "/",
				MaxAge:   86400,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   true,
			})
			http.Redirect(w, r, "/", http.StatusFound)
		})

		mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:     "zaman_sid",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
			http.Redirect(w, r, "/login", http.StatusFound)
		})
	}

	// Saved searches
	searchesFile := filepath.Join(dataDir, "zaman-searches.json")

	mux.HandleFunc("/web/searches", func(w http.ResponseWriter, r *http.Request) {
		if authOn {
			if u := getUser(r, tokenSecret); u == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			data, err := os.ReadFile(searchesFile)
			if err != nil {
				fmt.Fprint(w, "[]")
				return
			}
			w.Write(data)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Name   string            `json:"name"`
				Params map[string]string `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
				http.Error(w, `{"error":"name required"}`, http.StatusBadRequest)
				return
			}
			var searches []map[string]interface{}
			if data, err := os.ReadFile(searchesFile); err == nil {
				json.Unmarshal(data, &searches)
			}
			id := 1
			for _, s := range searches {
				if sid, ok := s["id"].(float64); ok && int(sid) >= id {
					id = int(sid) + 1
				}
			}
			searches = append(searches, map[string]interface{}{"id": id, "name": body.Name, "params": body.Params})
			os.MkdirAll(dataDir, 0o755)
			data, _ := json.Marshal(searches)
			os.WriteFile(searchesFile, data, 0o600)
			w.Write(data)
			return
		}
		if r.Method == http.MethodDelete {
			var body struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			var searches []map[string]interface{}
			if data, err := os.ReadFile(searchesFile); err == nil {
				json.Unmarshal(data, &searches)
			}
			var filtered []map[string]interface{}
			for _, s := range searches {
				if sid, ok := s["id"].(float64); ok && int(sid) != body.ID {
					filtered = append(filtered, s)
				}
			}
			data, _ := json.Marshal(filtered)
			os.WriteFile(searchesFile, data, 0o600)
			w.Write(data)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// Per-user dashboard preferences
	mux.HandleFunc("/web/prefs", func(w http.ResponseWriter, r *http.Request) {
		u := getUser(r, tokenSecret)
		if u == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		prefsFile := filepath.Join(dataDir, "zaman-prefs-"+u.Name+".json")
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			data, err := os.ReadFile(prefsFile)
			if err != nil {
				fmt.Fprint(w, "{}")
				return
			}
			w.Write(data)
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 16384))
			os.MkdirAll(dataDir, 0o755)
			os.WriteFile(prefsFile, body, 0o600)
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// Node names — rename HEP agents
	nodeNamesFile := filepath.Join(dataDir, "zaman-node-names.json")

	mux.HandleFunc("/web/node-names", func(w http.ResponseWriter, r *http.Request) {
		if authOn {
			if u := getUser(r, tokenSecret); u == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			data, err := os.ReadFile(nodeNamesFile)
			if err != nil {
				fmt.Fprint(w, "{}")
				return
			}
			w.Write(data)
			return
		}
		if r.Method == http.MethodPost {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			// Merge with existing
			existing := map[string]string{}
			if data, err := os.ReadFile(nodeNamesFile); err == nil {
				json.Unmarshal(data, &existing)
			}
			for k, v := range body {
				if v == "" {
					delete(existing, k)
				} else {
					existing[k] = v
				}
			}
			os.MkdirAll(dataDir, 0o755)
			data, _ := json.Marshal(existing)
			os.WriteFile(nodeNamesFile, data, 0o600)
			w.Write(data)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// User management API
	mux.HandleFunc("/web/users", func(w http.ResponseWriter, r *http.Request) {
		u := getUser(r, tokenSecret)
		if u == nil || u.Role != "admin" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			users := loadUsers(dataDir)
			// Strip password hashes
			type safeUser struct {
				ID   int    `json:"id"`
				Name string `json:"username"`
				Role string `json:"role"`
			}
			safe := make([]safeUser, len(users))
			for i, u := range users {
				safe[i] = safeUser{u.ID, u.Name, u.Role}
			}
			json.NewEncoder(w).Encode(safe)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Role     string `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			if body.Username == "" || body.Password == "" {
				http.Error(w, `{"error":"username and password required"}`, http.StatusBadRequest)
				return
			}
			if body.Role != "admin" && body.Role != "operator" && body.Role != "viewer" {
				body.Role = "viewer"
			}
			users := loadUsers(dataDir)
			for _, u := range users {
				if u.Name == body.Username {
					http.Error(w, `{"error":"username already exists"}`, http.StatusConflict)
					return
				}
			}
			salt := randomHex(16)
			ph := hashPW(salt, body.Password, hashRounds)
			maxID := 0
			for _, u := range users {
				if u.ID > maxID {
					maxID = u.ID
				}
			}
			users = append(users, user{ID: maxID + 1, Name: body.Username, PwHash: ph, Salt: salt, PwAlgo: "hmac-sha256", Rounds: hashRounds, Role: body.Role})
			saveUsers(dataDir, users)
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		if r.Method == http.MethodDelete {
			var body struct {
				ID int `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			if body.ID == u.ID {
				http.Error(w, `{"error":"cannot delete yourself"}`, http.StatusBadRequest)
				return
			}
			users := loadUsers(dataDir)
			filtered := users[:0]
			for _, u := range users {
				if u.ID != body.ID {
					filtered = append(filtered, u)
				}
			}
			saveUsers(dataDir, filtered)
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/web/users/password", func(w http.ResponseWriter, r *http.Request) {
		u := getUser(r, tokenSecret)
		if u == nil || u.Role != "admin" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			ID       int    `json:"id"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
			http.Error(w, `{"error":"id and password required"}`, http.StatusBadRequest)
			return
		}
		users := loadUsers(dataDir)
		for i, u := range users {
			if u.ID == body.ID {
				salt := randomHex(16)
				users[i].PwHash = hashPW(salt, body.Password, hashRounds)
				users[i].Salt = salt
				users[i].PwAlgo = "hmac-sha256"
				users[i].Rounds = hashRounds
				saveUsers(dataDir, users)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"ok":true}`)
				return
			}
		}
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
	})

	// API proxy
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if authOn {
			if u := getUser(r, tokenSecret); u == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		proxy.ServeHTTP(w, r)
	})

	// Prometheus metrics proxy
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	// Static files (SPA)
	staticDir := filepath.Join(filepath.Dir(os.Args[0]), "..", "web", "static")
	if _, err := os.Stat(staticDir); err != nil {
		// Try relative to working directory
		staticDir = "web/static"
		if _, err := os.Stat(staticDir); err != nil {
			staticDir = "static"
		}
	}
	fs := http.FileServer(http.Dir(staticDir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if authOn && r.URL.Path != "/login" {
			if u := getUser(r, tokenSecret); u == nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}
		// SPA: serve index.html for paths that don't match a real file
		path := filepath.Join(staticDir, r.URL.Path)
		if r.URL.Path != "/" {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				r.URL.Path = "/"
			}
		}
		fs.ServeHTTP(w, r)
	})

	log.Printf("zaman-web → http://127.0.0.1%s  (core %s, auth %s)",
		addr, coreURL, map[bool]string{true: "on", false: "off"}[authOn])
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---- auth ----

type user struct {
	ID      int    `json:"id"`
	Name    string `json:"username"`
	PwHash  string `json:"pw_hash"`
	Salt    string `json:"salt"`
	PwAlgo  string `json:"pw_algo"`
	Rounds  int    `json:"pw_rounds"`
	Role    string `json:"role"`
}

const hashRounds = 25000

func hashPW(salt, password string, rounds int) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	h := hex.EncodeToString(mac.Sum(nil))
	for i := 1; i < rounds; i++ {
		mac = hmac.New(sha256.New, []byte(salt))
		mac.Write([]byte(h))
		h = hex.EncodeToString(mac.Sum(nil))
	}
	return h
}

func loadUsers(dataDir string) []user {
	data, err := os.ReadFile(filepath.Join(dataDir, "zaman-users.json"))
	if err != nil {
		return nil
	}
	var users []user
	json.Unmarshal(data, &users)
	return users
}

func saveUsers(dataDir string, users []user) {
	os.MkdirAll(dataDir, 0o755)
	data, _ := json.Marshal(users)
	path := filepath.Join(dataDir, "zaman-users.json")
	os.WriteFile(path, data, 0o600)
}

func initAdmin(dataDir, secret string) {
	users := loadUsers(dataDir)
	if len(users) > 0 {
		return
	}
	pw := randomHex(8)
	salt := randomHex(16)
	h := hashPW(salt, pw, hashRounds)
	admin := user{ID: 1, Name: "admin", PwHash: h, Salt: salt, PwAlgo: "hmac-sha256", Rounds: hashRounds, Role: "admin"}
	saveUsers(dataDir, []user{admin})
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────┐")
	fmt.Println("  │  Default admin account created                │")
	fmt.Println("  │  username: admin                              │")
	fmt.Printf("  │  password: %-16s                  │\n", pw)
	fmt.Println("  │  Change this immediately.                     │")
	fmt.Println("  └──────────────────────────────────────────────┘")
	fmt.Println()
}

func doLogin(dataDir, secret, username, password string) string {
	users := loadUsers(dataDir)
	for _, u := range users {
		if u.Name != username {
			continue
		}
		rounds := u.Rounds
		if rounds == 0 {
			rounds = 1000
		}
		got := hashPW(u.Salt, password, rounds)
		if !hmac.Equal([]byte(got), []byte(u.PwHash)) {
			// Legacy fallback
			if u.Rounds == 0 {
				legacy := hashPW(u.Salt, password, 1000)
				if !hmac.Equal([]byte(legacy), []byte(u.PwHash)) {
					return ""
				}
			} else {
				return ""
			}
		}
		return makeToken(secret, u)
	}
	return ""
}

func makeToken(secret string, u user) string {
	expires := time.Now().Unix() + 86400
	payload := fmt.Sprintf("%d:%s:%s:%d", u.ID, u.Name, u.Role, expires)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.StdEncoding.EncodeToString([]byte(payload + ":" + sig))
}

func verifyToken(secret, token string) *user {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil
	}
	s := string(raw)
	if len(s) < 66 {
		return nil
	}
	sigStart := len(s) - 64
	if s[sigStart-1] != ':' {
		return nil
	}
	payload := s[:sigStart-1]
	gotSig := s[sigStart:]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotSig), []byte(expected)) {
		return nil
	}
	parts := strings.Split(payload, ":")
	if len(parts) < 4 {
		return nil
	}
	expires, _ := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if expires < time.Now().Unix() {
		return nil
	}
	id, _ := strconv.Atoi(parts[0])
	role := parts[len(parts)-2]
	uname := strings.Join(parts[1:len(parts)-2], ":")
	return &user{ID: id, Name: uname, Role: role}
}

func getUser(r *http.Request, secret string) *user {
	// Check X-API-Key header (SPA stores key in localStorage)
	if k := r.Header.Get("X-API-Key"); k != "" && apiKeyGlobal != "" {
		if hmac.Equal([]byte(k), []byte(apiKeyGlobal)) {
			return &user{ID: 0, Name: "api", Role: "admin"}
		}
	}
	// Check Authorization: Bearer header
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tok := auth[7:]
		if apiKeyGlobal != "" && hmac.Equal([]byte(tok), []byte(apiKeyGlobal)) {
			return &user{ID: 0, Name: "api", Role: "admin"}
		}
	}
	// Fall back to session cookie
	c, err := r.Cookie("zaman_sid")
	if err != nil || c.Value == "" {
		return nil
	}
	return verifyToken(secret, c.Value)
}

var apiKeyGlobal string

// ---- rate limiter ----

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]int64
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{attempts: make(map[string][]int64)}
}

func (rl *rateLimiter) record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.attempts[ip] = append(rl.attempts[ip], time.Now().Unix())
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Unix() - 60
	kept := rl.attempts[ip][:0]
	for _, ts := range rl.attempts[ip] {
		if ts >= cutoff {
			kept = append(kept, ts)
		}
	}
	rl.attempts[ip] = kept
	return len(kept) < 5
}

// ---- helpers ----

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func loadOrCreateSecret(dataDir string) string {
	path := filepath.Join(dataDir, "zaman-web-secret.key")
	data, err := os.ReadFile(path)
	if err == nil && len(data) >= 32 {
		return strings.TrimSpace(string(data))
	}
	os.MkdirAll(dataDir, 0o755)
	secret := randomHex(32)
	os.WriteFile(path, []byte(secret), 0o600)
	return secret
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

func serveLoginPage(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="flex items-center gap-2 rounded-xl border border-[rgba(248,113,113,.3)] bg-[rgba(248,113,113,.06)] px-4 py-3 text-sm text-[#f87171] mb-5">` +
			`<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>` +
			errMsg + `</div>`
	}
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="icon" type="image/svg+xml" href="/favicon.svg"/>
<title>Login · Zaman</title>
<script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
<style type="text/tailwindcss">
@theme{--color-ink:#fafafa;--color-bg:#09090b;--color-panel:#18181b;--color-line:#27272a;--color-accent:#a78bfa;}
:root{--z-bg:#09090b;--z-surface:#111114;--z-panel:#18181b;--z-line:#1e1e22;--z-ink:#e4e4e7;--z-muted:#71717a;--z-field:#111114}
html[data-theme='light']{--z-bg:#f7f7f8;--z-surface:#ffffff;--z-panel:#ffffff;--z-line:#d9d9df;--z-ink:#18181b;--z-muted:#52525b;--z-field:#ffffff;color-scheme:light}
html[data-theme='dark']{color-scheme:dark}
input:focus{border-color:#a78bfa!important;box-shadow:0 0 0 3px rgba(167,139,250,.15)!important}
.login-card{background:color-mix(in srgb,var(--z-panel) 88%%,transparent);backdrop-filter:blur(20px)}
@keyframes fadein{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.fade-in{animation:fadein .4s ease-out}
</style>
<script>(function(){var t=localStorage.getItem('zaman-theme')||'dark';document.documentElement.dataset.theme=t})();</script>
</head>
<body class="min-h-screen" style="background:var(--z-bg);color:var(--z-ink)">
<main class="min-h-screen grid place-items-center px-5 py-8">
<div class="w-full max-w-[420px] fade-in">
<div class="flex flex-col items-center mb-8">
<div class="w-14 h-14 rounded-2xl bg-gradient-to-br from-[#a78bfa] to-[#6d28d9] grid place-items-center font-black text-xl text-[#09090b] mb-4 shadow-lg shadow-[rgba(167,139,250,.2)]">Z</div>
<h1 class="text-2xl font-bold tracking-tight">Zaman</h1>
<p class="text-sm mt-1" style="color:var(--z-muted)">SIP monitoring · echo · metrics</p></div>
%s
<form method="post" action="/login" class="login-card rounded-xl border p-7 space-y-5" style="border-color:var(--z-line)">
<div><label class="block text-[11px] font-semibold uppercase mb-2" style="color:var(--z-muted);letter-spacing:.08em">Username</label>
<input name="username" required autofocus autocomplete="username" class="w-full rounded-lg border px-4 py-3 text-sm outline-none" style="background:var(--z-field);border-color:var(--z-line);color:var(--z-ink)" placeholder="admin"/></div>
<div><label class="block text-[11px] font-semibold uppercase mb-2" style="color:var(--z-muted);letter-spacing:.08em">Password</label>
<input name="password" type="password" required autocomplete="current-password" class="w-full rounded-lg border px-4 py-3 text-sm outline-none" style="background:var(--z-field);border-color:var(--z-line);color:var(--z-ink)"/></div>
<button type="submit" class="w-full rounded-lg px-4 py-3 text-sm font-semibold bg-gradient-to-r from-[#8b5cf6] to-[#7c3aed] text-white shadow-lg shadow-[rgba(124,58,237,.22)] hover:brightness-110 cursor-pointer">Sign in</button>
</form>
<p class="text-center text-xs mt-6" style="color:var(--z-muted)">Integrated SIP monitoring and operations console</p>
</div></main></body></html>`, errHTML)
}
