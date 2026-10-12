package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// SIPInfo holds parsed SIP message fields.
type SIPInfo struct {
	Method  string
	Status  int
	Kind    string // "request" or "response"
	CallID  string
	From    string
	To      string
	CSeq    string
	RURI    string
}

// parseSIP extracts key fields from a SIP message.
func parseSIP(msg string) SIPInfo {
	var info SIPInfo
	lines := strings.SplitN(msg, "\n", 2)
	if len(lines) == 0 {
		return info
	}

	firstLine := strings.TrimSpace(lines[0])
	if strings.HasPrefix(firstLine, "SIP/") {
		// Response: SIP/2.0 200 OK
		info.Kind = "response"
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &info.Status)
		}
	} else {
		// Request: INVITE sip:user@host SIP/2.0
		info.Kind = "request"
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 1 {
			info.Method = strings.ToUpper(parts[0])
		}
		if len(parts) >= 2 {
			info.RURI = parts[1]
		}
	}

	// Parse headers (case-insensitive)
	if len(lines) > 1 {
		for _, line := range strings.Split(lines[1], "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				break // end of headers
			}
			colonIdx := strings.Index(line, ":")
			if colonIdx < 1 {
				continue
			}
			name := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])

			switch strings.ToLower(name) {
			case "call-id", "i":
				info.CallID = value
			case "from", "f":
				info.From = value
			case "to", "t":
				info.To = value
			case "cseq":
				info.CSeq = value
				// For responses, extract method from CSeq
				if info.Kind == "response" && info.Method == "" {
					parts := strings.Fields(value)
					if len(parts) >= 2 {
						info.Method = strings.ToUpper(parts[1])
					}
				}
			}
		}
	}

	return info
}

// redactSIP removes Authorization and Proxy-Authorization headers.
func redactSIP(msg string) string {
	var b strings.Builder
	b.Grow(len(msg))
	for _, line := range strings.Split(msg, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "authorization:") ||
			strings.HasPrefix(lower, "proxy-authorization:") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// sdpExtract parses SDP from the message body.
func sdpExtract(msg string) (codecs []string, mediaPort int, srtp bool) {
	// Find body after blank line
	idx := strings.Index(msg, "\r\n\r\n")
	if idx < 0 {
		idx = strings.Index(msg, "\n\n")
	}
	if idx < 0 {
		return
	}
	body := msg[idx:]

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "m=audio ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				fmt.Sscanf(parts[1], "%d", &mediaPort)
			}
			if strings.Contains(line, "SAVP") || strings.Contains(line, "savp") {
				srtp = true
			}
		}
		if strings.HasPrefix(line, "a=rtpmap:") {
			// a=rtpmap:0 PCMU/8000
			parts := strings.SplitN(line, " ", 2)
			if len(parts) == 2 {
				codec := strings.SplitN(parts[1], "/", 2)[0]
				codecs = append(codecs, codec)
			}
		}
		if strings.HasPrefix(line, "a=crypto:") {
			srtp = true
		}
	}
	return
}

// makeRecord builds a JSON capture record from a SIP message.
func makeRecord(src, dst, transport, msg, agent, proto string, tsMs int64,
	hepNodeID int, hepNodeName, hepCorrelation string) string {

	redacted := redactSIP(msg)
	info := parseSIP(msg)

	raw64 := base64.StdEncoding.EncodeToString([]byte(redacted))

	// Build method field: for responses, prefix with status class
	method := info.Method
	if info.Kind == "response" && info.Status > 0 && method != "" {
		// Store as "200 INVITE", "486 INVITE", etc.
		// But use CSeq-style: status/100 prefix for bucketing in reports
		statusClass := info.Status / 100
		method = fmt.Sprintf("%d %s", statusClass, info.Method)
	}

	var b strings.Builder
	b.Grow(512)
	fmt.Fprintf(&b, `{"ts_ms":%d,"src":"%s","dst":"%s","transport":"%s","proto":"%s","agent":"%s"`,
		tsMs, jesc(src), jesc(dst), jesc(transport), jesc(proto), jesc(agent))
	fmt.Fprintf(&b, `,"kind":"%s","method":"%s","status":%d`,
		info.Kind, jesc(method), info.Status)
	if info.RURI != "" {
		fmt.Fprintf(&b, `,"ruri":"%s"`, jesc(info.RURI))
	}
	if info.CallID != "" {
		fmt.Fprintf(&b, `,"call_id":"%s"`, jesc(info.CallID))
	}
	if info.From != "" {
		fmt.Fprintf(&b, `,"from":"%s"`, jesc(info.From))
	}
	if info.To != "" {
		fmt.Fprintf(&b, `,"to":"%s"`, jesc(info.To))
	}
	if info.CSeq != "" {
		fmt.Fprintf(&b, `,"cseq":"%s"`, jesc(info.CSeq))
	}
	if hepNodeID > 0 {
		fmt.Fprintf(&b, `,"hep_node_id":%d`, hepNodeID)
	}
	if hepNodeName != "" {
		fmt.Fprintf(&b, `,"hep_node":"%s"`, jesc(hepNodeName))
	}
	if hepCorrelation != "" {
		fmt.Fprintf(&b, `,"hep_cid":"%s"`, jesc(hepCorrelation))
	}
	fmt.Fprintf(&b, `,"size":%d,"raw_b64":"%s"}`, len(msg), raw64)

	return b.String()
}

// echoAllowed checks if a method should get an echo reply.
func echoAllowed(method string, cfg *Config) bool {
	if cfg.EchoAll {
		return true
	}
	echoMethods := env("ZAMAN_ECHO_METHODS", "OPTIONS")
	if strings.EqualFold(echoMethods, "ALL") {
		return true
	}
	for _, m := range strings.Split(echoMethods, ",") {
		if strings.EqualFold(strings.TrimSpace(m), method) {
			return true
		}
	}
	return false
}

// buildEcho generates a SIP response for echo.
func buildEcho(msg, localHost string, localPort int) string {
	info := parseSIP(msg)
	if info.Kind != "request" {
		return ""
	}

	// Extract Via, From, To, Call-ID, CSeq from original
	var via, from, to, callID, cseq string
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		colonIdx := strings.Index(line, ":")
		if colonIdx < 1 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])
		switch name {
		case "via", "v":
			if via == "" {
				via = value
			}
		case "from", "f":
			from = value
		case "to", "t":
			to = value
		case "call-id", "i":
			callID = value
		case "cseq":
			cseq = value
		}
		_ = lower
	}

	status := "200 OK"
	if info.Method == "REGISTER" {
		status = "401 Unauthorized"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %s\r\n", status)
	fmt.Fprintf(&b, "Via: %s\r\n", via)
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Call-ID: %s\r\n", callID)
	fmt.Fprintf(&b, "CSeq: %s\r\n", cseq)
	fmt.Fprintf(&b, "Contact: <sip:%s:%d>\r\n", localHost, localPort)
	fmt.Fprintf(&b, "Server: Zaman/%s\r\n", Version)
	if info.Method == "OPTIONS" {
		b.WriteString("Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,REGISTER,INFO\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// sipWorker listens for SIP UDP packets.
func sipWorker(ctx context.Context, cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) {
	addr := fmt.Sprintf("%s:%d", cfg.SIPHost, cfg.SIPPort)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("sip: listen %s: %v", addr, err)
		return
	}
	defer pc.Close()

	log.Printf("sip: listening on %s", addr)

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, remoteAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}

		msg := string(buf[:n])
		if len(msg) < 20 {
			continue
		}

		src := remoteAddr.String()
		dst := addr
		tsMs := time.Now().UnixMilli()

		info := parseSIP(msg)
		metrics.Inc(&metrics.MsgsTotal, 1)
		if info.Kind == "request" {
			metrics.Inc(&metrics.Requests, 1)
		} else {
			metrics.Inc(&metrics.Responses, 1)
		}
		if info.Status >= 200 && info.Status < 300 {
			metrics.Inc(&metrics.Status2xx, 1)
		} else if info.Status >= 400 {
			metrics.Inc(&metrics.Status4xx5xx, 1)
		}
		metrics.BumpMethod(info.Method)

		rec := makeRecord(src, dst, "UDP", msg, "sip-native", "sip", tsMs, 0, "", "")
		ring.Push(rec)

		select {
		case dbCh <- rec:
			// queued
		default:
			metrics.Inc(&metrics.DBDrop, 1)
		}

		// Echo reply
		if info.Kind == "request" && echoAllowed(info.Method, cfg) {
			reply := buildEcho(msg, cfg.SIPHost, cfg.SIPPort)
			if reply != "" {
				pc.WriteTo([]byte(reply), remoteAddr)
				metrics.Inc(&metrics.Echoes, 1)
			}
		}
	}
}
