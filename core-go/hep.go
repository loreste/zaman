package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// HEPInfo holds decoded HEP3 packet fields.
type HEPInfo struct {
	OK            bool
	Version       byte
	IPProto       byte // 4=IPv4, 6=IPv6
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	TSec          uint32
	TUsec         uint32
	ProtoType     byte // 1=SIP, 5=RTCP, 34=RTP, 35=RTCPXR
	NodeID        uint32
	NodePW        string
	NodeName      string
	CorrelationID string
	Payload       []byte
}

func (h *HEPInfo) TsMs() int64 {
	return int64(h.TSec)*1000 + int64(h.TUsec)/1000
}

func (h *HEPInfo) Endpoint(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func (h *HEPInfo) Src() string { return h.Endpoint(h.SrcIP, h.SrcPort) }
func (h *HEPInfo) Dst() string { return h.Endpoint(h.DstIP, h.DstPort) }

func (h *HEPInfo) AgentLabel() string {
	if h.NodeName != "" {
		return h.NodeName
	}
	if h.NodeID > 0 {
		return fmt.Sprintf("hep-%d", h.NodeID)
	}
	return "hep-0"
}

func protoTypeName(t byte) string {
	switch t {
	case 1:
		return "sip"
	case 5:
		return "rtcp"
	case 34:
		return "rtpagent"
	case 35:
		return "rtcpxr"
	case 38:
		return "horaclifix"
	case 53:
		return "dns"
	case 100:
		return "log"
	default:
		return "unknown"
	}
}

// hepDecode parses a binary HEP3 packet.
func hepDecode(pkt []byte) HEPInfo {
	var info HEPInfo
	if len(pkt) < 6 {
		return info
	}
	// Check magic "HEP3" or "\x48\x45\x50\x33"
	if pkt[0] != 'H' || pkt[1] != 'E' || pkt[2] != 'P' || pkt[3] != '3' {
		return info
	}
	totalLen := binary.BigEndian.Uint16(pkt[4:6])
	if int(totalLen) > len(pkt) {
		totalLen = uint16(len(pkt))
	}

	offset := 6
	for offset+6 <= int(totalLen) {
		// Each chunk: vendor(2) + type(2) + length(2) + data
		// vendor := binary.BigEndian.Uint16(pkt[offset:])
		chunkType := binary.BigEndian.Uint16(pkt[offset+2:])
		chunkLen := binary.BigEndian.Uint16(pkt[offset+4:])
		if chunkLen < 6 || offset+int(chunkLen) > int(totalLen) {
			break
		}
		data := pkt[offset+6 : offset+int(chunkLen)]

		switch chunkType {
		case 1: // IP protocol family
			if len(data) >= 1 {
				info.IPProto = data[0]
			}
		case 2: // IP protocol ID (UDP=17, TCP=6)
			// skip
		case 3: // IPv4 src
			if len(data) >= 4 {
				info.SrcIP = fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
			}
		case 4: // IPv4 dst
			if len(data) >= 4 {
				info.DstIP = fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
			}
		case 5: // IPv6 src
			if len(data) >= 16 {
				info.SrcIP = ipv6String(data[:16])
			}
		case 6: // IPv6 dst
			if len(data) >= 16 {
				info.DstIP = ipv6String(data[:16])
			}
		case 7: // src port
			if len(data) >= 2 {
				info.SrcPort = binary.BigEndian.Uint16(data)
			}
		case 8: // dst port
			if len(data) >= 2 {
				info.DstPort = binary.BigEndian.Uint16(data)
			}
		case 9: // timestamp seconds
			if len(data) >= 4 {
				info.TSec = binary.BigEndian.Uint32(data)
			}
		case 10: // timestamp microseconds
			if len(data) >= 4 {
				info.TUsec = binary.BigEndian.Uint32(data)
			}
		case 11: // proto type
			if len(data) >= 1 {
				info.ProtoType = data[0]
			}
		case 12: // capture agent ID
			if len(data) >= 4 {
				info.NodeID = binary.BigEndian.Uint32(data)
			} else if len(data) >= 2 {
				info.NodeID = uint32(binary.BigEndian.Uint16(data))
			}
		case 14: // auth key / password
			info.NodePW = string(data)
		case 15: // payload
			info.Payload = make([]byte, len(data))
			copy(info.Payload, data)
		case 17: // correlation ID
			info.CorrelationID = string(data)
		case 19: // capture agent name
			info.NodeName = strings.TrimRight(string(data), "\x00")
		}

		offset += int(chunkLen)
	}

	info.OK = len(info.Payload) > 0 || info.ProtoType > 0
	info.Version = 3
	return info
}

func ipv6String(b []byte) string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		binary.BigEndian.Uint16(b[0:2]),
		binary.BigEndian.Uint16(b[2:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		binary.BigEndian.Uint16(b[10:12]),
		binary.BigEndian.Uint16(b[12:14]),
		binary.BigEndian.Uint16(b[14:16]))
}

// hepPasswordOK checks HEP packet auth.
func hepPasswordOK(info *HEPInfo, cfg *Config) bool {
	if cfg.HEPPassword == "" {
		return true
	}
	return constantTimeEqual(info.NodePW, cfg.HEPPassword)
}

// hepPeerAllowed checks the HEP peer allowlist.
func hepPeerAllowed(peer string, cfg *Config) bool {
	if len(cfg.HEPAllow) == 0 {
		return true
	}
	host, _, _ := net.SplitHostPort(peer)
	if host == "" {
		host = peer
	}
	for _, allowed := range cfg.HEPAllow {
		if host == allowed || strings.HasPrefix(host, allowed) {
			return true
		}
	}
	return false
}

// handleHEPPacket processes a single HEP3 packet.
func handleHEPPacket(pkt []byte, transport string, peer string,
	cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) {

	info := hepDecode(pkt)
	if !info.OK {
		metrics.Inc(&metrics.HEPErr, 1)
		return
	}

	metrics.Inc(&metrics.HEPTotal, 1)
	switch transport {
	case "HEP3":
		metrics.Inc(&metrics.HEPUDP, 1)
	case "HEP3/TCP":
		metrics.Inc(&metrics.HEPTCP, 1)
	case "HEP3/TLS":
		metrics.Inc(&metrics.HEPTLS, 1)
	}

	if !hepPasswordOK(&info, cfg) {
		metrics.Inc(&metrics.HEPAuthFail, 1)
		return
	}

	if !hepPeerAllowed(peer, cfg) {
		metrics.Inc(&metrics.HEPDeny, 1)
		return
	}

	proto := protoTypeName(info.ProtoType)
	switch proto {
	case "sip":
		metrics.Inc(&metrics.HEPSIP, 1)
	case "rtcp":
		metrics.Inc(&metrics.HEPRTCP, 1)
	case "rtpagent":
		metrics.Inc(&metrics.HEPRTP, 1)
	case "rtcpxr":
		metrics.Inc(&metrics.HEPRTCPXR, 1)
	default:
		metrics.Inc(&metrics.HEPOther, 1)
	}

	tsMs := info.TsMs()
	if tsMs <= 0 {
		tsMs = time.Now().UnixMilli()
	}

	msg := string(info.Payload)
	sipInfo := parseSIP(msg)

	metrics.Inc(&metrics.MsgsTotal, 1)
	if sipInfo.Kind == "request" {
		metrics.Inc(&metrics.Requests, 1)
	} else {
		metrics.Inc(&metrics.Responses, 1)
	}
	if sipInfo.Status >= 200 && sipInfo.Status < 300 {
		metrics.Inc(&metrics.Status2xx, 1)
	} else if sipInfo.Status >= 400 {
		metrics.Inc(&metrics.Status4xx5xx, 1)
	}
	metrics.BumpMethod(sipInfo.Method)

	rec := makeRecord(info.Src(), info.Dst(), transport, msg,
		info.AgentLabel(), proto, tsMs,
		int(info.NodeID), info.NodeName, info.CorrelationID)

	ring.Push(rec)

	select {
	case dbCh <- rec:
	default:
		metrics.Inc(&metrics.DBDrop, 1)
	}
}

// hepUDPWorker listens for HEP3 packets over UDP.
func hepUDPWorker(ctx context.Context, cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) {
	addr := fmt.Sprintf("%s:%d", cfg.SIPHost, cfg.HEPPort)
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("hep/udp: listen %s: %v", addr, err)
		return
	}
	defer pc.Close()

	log.Printf("hep/udp: listening on %s", addr)

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

		if n < 10 {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		handleHEPPacket(pkt, "HEP3", remoteAddr.String(), cfg, metrics, ring, dbCh)
	}
}

// hepTCPWorker listens for HEP3 over TCP.
func hepTCPWorker(ctx context.Context, cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) {
	addr := fmt.Sprintf("%s:%d", cfg.SIPHost, cfg.HEPTCPPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("hep/tcp: listen %s: %v", addr, err)
		return
	}
	defer ln.Close()

	log.Printf("hep/tcp: listening on %s", addr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ln.(*net.TCPListener).SetDeadline(time.Now().Add(500 * time.Millisecond))
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			continue
		}

		go hepTCPSession(ctx, conn, cfg, metrics, ring, dbCh)
	}
}

func hepTCPSession(ctx context.Context, conn net.Conn, cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) {
	defer conn.Close()

	peer := conn.RemoteAddr().String()
	if !hepPeerAllowed(peer, cfg) {
		metrics.Inc(&metrics.HEPDeny, 1)
		return
	}

	buf := make([]byte, 0, 32768)
	tmp := make([]byte, 16384)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			// Cap at 2MB
			if len(buf) > 2*1024*1024 {
				return
			}
		}

		// Drain complete frames
		buf = drainHEPFrames(buf, "HEP3/TCP", peer, cfg, metrics, ring, dbCh)

		if err != nil {
			if err == io.EOF {
				drainHEPFrames(buf, "HEP3/TCP", peer, cfg, metrics, ring, dbCh)
			}
			return
		}
	}
}

// hepTLSWorker listens for HEP3 over TLS.
func hepTLSWorker(ctx context.Context, cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) {
	cert, err := tls.LoadX509KeyPair(cfg.HEPTLSCert, cfg.HEPTLSKey)
	if err != nil {
		log.Printf("hep/tls: cert error: %v", err)
		return
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf("%s:%d", cfg.SIPHost, cfg.HEPTLSPort)
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		log.Printf("hep/tls: listen %s: %v", addr, err)
		return
	}
	defer ln.Close()

	log.Printf("hep/tls: listening on %s", addr)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		go func() {
			defer conn.Close()
			peer := conn.RemoteAddr().String()
			if !hepPeerAllowed(peer, cfg) {
				metrics.Inc(&metrics.HEPDeny, 1)
				return
			}
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			data, err := io.ReadAll(io.LimitReader(conn, 2*1024*1024))
			if err != nil || len(data) == 0 {
				return
			}
			drainHEPFrames(data, "HEP3/TLS", peer, cfg, metrics, ring, dbCh)
		}()
	}
}

// drainHEPFrames extracts complete HEP3 frames from a buffer.
func drainHEPFrames(buf []byte, transport, peer string,
	cfg *Config, metrics *Metrics, ring *Ring, dbCh chan<- string) []byte {

	for len(buf) >= 6 {
		// Look for HEP3 magic
		if buf[0] != 'H' || buf[1] != 'E' || buf[2] != 'P' || buf[3] != '3' {
			// Resync: skip one byte
			buf = buf[1:]
			continue
		}
		frameLen := int(binary.BigEndian.Uint16(buf[4:6]))
		if frameLen < 6 || frameLen > 65535 {
			buf = buf[1:]
			continue
		}
		if len(buf) < frameLen {
			break // incomplete frame
		}
		handleHEPPacket(buf[:frameLen], transport, peer, cfg, metrics, ring, dbCh)
		buf = buf[frameLen:]
	}
	return buf
}
