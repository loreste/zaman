package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// mosFromJitterLoss calculates MOS*10 using ITU-T G.107 simplified R-factor.
func mosFromJitterLoss(jitterMs, lossPct float64) int {
	r := 93.0 - (jitterMs / 10.0) - (lossPct * 2.5)
	if r < 0 {
		r = 0
	}
	if r > 100 {
		r = 100
	}
	// R-factor to MOS conversion
	var mos float64
	if r < 6.5 {
		mos = 1.0
	} else if r > 100 {
		mos = 4.5
	} else {
		mos = 1.0 + 0.035*r + r*(r-60)*(100-r)*7e-6
	}
	return int(math.Round(mos * 10))
}

// rFactorFromJitterLoss returns R-factor 0-100.
func rFactorFromJitterLoss(jitterMs, lossPct float64) int {
	r := 93.0 - (jitterMs / 10.0) - (lossPct * 2.5)
	if r < 0 {
		return 0
	}
	if r > 100 {
		return 100
	}
	return int(r)
}

// rtcpParseQoS extracts QoS metrics from an RTCP packet (SR/RR).
func rtcpParseQoS(payload []byte) string {
	if len(payload) < 8 {
		return ""
	}

	var worstMos int = 50 // 5.0 * 10
	var maxJitter float64
	var maxLoss float64
	var blocks []string

	offset := 0
	for offset+4 <= len(payload) {
		// RTCP header: V(2) P(1) RC(5) PT(8) Length(16)
		if offset+4 > len(payload) {
			break
		}
		header := payload[offset]
		version := (header >> 6) & 0x03
		if version != 2 {
			break
		}
		rc := int(header & 0x1F)
		pt := payload[offset+1]
		length := int(binary.BigEndian.Uint16(payload[offset+2:])) * 4

		if pt != 200 && pt != 201 { // SR=200, RR=201
			offset += length + 4
			continue
		}

		// Skip header + SSRC
		blockStart := offset + 8
		if pt == 200 {
			blockStart = offset + 28 // SR has sender info (20 bytes)
		}

		for i := 0; i < rc && blockStart+24 <= len(payload); i++ {
			block := payload[blockStart : blockStart+24]
			fractionLost := float64(block[4]) / 256.0 * 100.0
			jitter := float64(binary.BigEndian.Uint32(block[12:16]))

			// Convert jitter from timestamp units to ms (assume 8kHz)
			jitterMs := jitter / 8.0

			if jitterMs > maxJitter {
				maxJitter = jitterMs
			}
			if fractionLost > maxLoss {
				maxLoss = fractionLost
			}

			mos := mosFromJitterLoss(jitterMs, fractionLost)
			if mos < worstMos {
				worstMos = mos
			}

			ssrc := binary.BigEndian.Uint32(block[0:4])
			blocks = append(blocks, fmt.Sprintf(
				`{"ssrc":%d,"fraction_lost":%.1f,"jitter_ms":%.1f,"mos_x10":%d}`,
				ssrc, fractionLost, jitterMs, mos))

			blockStart += 24
		}

		offset += length + 4
	}

	if len(blocks) == 0 {
		return ""
	}

	rFactor := rFactorFromJitterLoss(maxJitter, maxLoss)

	return fmt.Sprintf(`{"jitter_ms":%.1f,"loss_pct":%.1f,"mos_x10":%d,"r_factor":%d,"blocks":[%s]}`,
		maxJitter, maxLoss, worstMos, rFactor, strings.Join(blocks, ","))
}

// rtpCodecName maps RTP payload type to codec name.
func rtpCodecName(pt int) string {
	switch pt {
	case 0:
		return "PCMU"
	case 3:
		return "GSM"
	case 4:
		return "G723"
	case 8:
		return "PCMA"
	case 9:
		return "G722"
	case 18:
		return "G729"
	case 101:
		return "telephone-event"
	case 111, 112:
		return "opus"
	default:
		if pt >= 96 {
			return "dynamic"
		}
		return "unknown"
	}
}
