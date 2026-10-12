package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// doProbe sends a SIP OPTIONS to a host and measures RTT.
func doProbe(cfg *Config, metrics *Metrics, bodyJSON string) string {
	if !cfg.ProbeEnabled {
		return `{"ok":false,"error":"probe disabled (set ZAMAN_PROBE=1)"}`
	}

	var req struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		WaitMs int    `json:"wait_ms"`
	}
	if err := json.Unmarshal([]byte(bodyJSON), &req); err != nil {
		return `{"ok":false,"error":"invalid json"}`
	}

	if req.Host == "" {
		return `{"ok":false,"error":"host required"}`
	}
	if req.Port <= 0 || req.Port > 65535 {
		req.Port = 5060
	}
	if req.WaitMs <= 0 || req.WaitMs > 5000 {
		req.WaitMs = 3000
	}

	// Block dangerous targets
	if isBlockedHost(req.Host, cfg) {
		return `{"ok":false,"error":"host blocked"}`
	}

	addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
	conn, err := net.DialTimeout("udp", addr, time.Duration(req.WaitMs)*time.Millisecond)
	if err != nil {
		metrics.Inc(&metrics.ProbesFail, 1)
		return fmt.Sprintf(`{"ok":false,"error":"%s"}`, jesc(err.Error()))
	}
	defer conn.Close()

	callID := fmt.Sprintf("zaman-probe-%d@%s", time.Now().UnixNano(), "zaman.local")
	branch := fmt.Sprintf("z9hG4bK-%d", time.Now().UnixNano())
	localAddr := conn.LocalAddr().String()

	msg := fmt.Sprintf("OPTIONS sip:echo@%s SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP %s;rport;branch=%s\r\n"+
		"From: Zaman Probe <sip:probe@zaman.local>;tag=prb%d\r\n"+
		"To: <sip:echo@%s>\r\n"+
		"Call-ID: %s\r\n"+
		"CSeq: 1 OPTIONS\r\n"+
		"User-Agent: Zaman-Probe/%s\r\n"+
		"Max-Forwards: 70\r\n"+
		"Content-Length: 0\r\n\r\n",
		req.Host, localAddr, branch, time.Now().UnixNano()%100000,
		req.Host, callID, Version)

	t0 := time.Now()
	conn.Write([]byte(msg))

	conn.SetReadDeadline(time.Now().Add(time.Duration(req.WaitMs) * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	rttMs := time.Since(t0).Milliseconds()

	if err != nil {
		metrics.Inc(&metrics.ProbesFail, 1)
		return fmt.Sprintf(`{"ok":false,"host":"%s","port":%d,"error":"timeout","rtt_ms":%d,"call_id":"%s"}`,
			jesc(req.Host), req.Port, rttMs, jesc(callID))
	}

	resp := string(buf[:n])
	info := parseSIP(resp)

	metrics.Inc(&metrics.ProbesOk, 1)
	metrics.mu.Lock()
	metrics.ProbeRTT = rttMs
	metrics.mu.Unlock()

	return fmt.Sprintf(`{"ok":true,"host":"%s","port":%d,"status":%d,"rtt_ms":%d,"call_id":"%s"}`,
		jesc(req.Host), req.Port, info.Status, rttMs, jesc(callID))
}

func isBlockedHost(host string, cfg *Config) bool {
	// Block metadata endpoints
	lower := strings.ToLower(host)
	if lower == "metadata.google.internal" || strings.HasPrefix(host, "169.254.") {
		return true
	}
	// Block private IPs unless override
	if !cfg.ProbeAllowPrivate && isPrivateIP(host) {
		return true
	}
	return false
}

func isPrivateIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	private := []string{"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127."}
	s := ip.String()
	for _, p := range private {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
