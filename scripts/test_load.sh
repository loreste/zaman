#!/bin/bash
# Zaman load test — sustained HEP ingestion benchmark
# Usage: ./scripts/test_load.sh [messages_per_second] [duration_seconds]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MPS="${1:-500}"
DURATION="${2:-10}"
HEP_PORT="${3:-19070}"
API_PORT="${4:-19095}"
TOTAL=$((MPS * DURATION))

echo ""
echo "Zaman Load Test"
echo "==============="
echo "  Target: ${MPS} msg/s for ${DURATION}s = ${TOTAL} messages"
echo "  HEP port: ${HEP_PORT}, API port: ${API_PORT}"
echo ""

# Start core if not running
if ! curl -fs "http://127.0.0.1:${API_PORT}/api/health" >/dev/null 2>&1; then
    echo "Starting core..."
    rm -f data/loadtest.db data/loadtest.db-*
    ZAMAN_DB=data/loadtest.db ./bin/zaman-core 15071 $HEP_PORT $API_PORT >data/loadtest.log 2>&1 &
    CORE_PID=$!
    trap "kill $CORE_PID 2>/dev/null" EXIT
    for i in $(seq 1 60); do
        curl -fs "http://127.0.0.1:${API_PORT}/api/health" >/dev/null 2>&1 && break
        sleep 0.1
    done
fi

# Get baseline
BEFORE=$(curl -s "http://127.0.0.1:${API_PORT}/api/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("captures",0))' 2>/dev/null || echo 0)
DB_ERR_BEFORE=$(curl -s "http://127.0.0.1:${API_PORT}/api/health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["db"]["writes_err"])' 2>/dev/null || echo 0)

echo "Sending ${TOTAL} HEP packets..."
T0=$(python3 -c 'import time;print(time.time())')

python3 -c "
import socket, struct, time, sys

def chunk(tid, val, vendor=0):
    return struct.pack('!HHH', vendor, tid, 6+len(val)) + val

def hep3(payload, src_ip, dst_ip, node, cid):
    now = time.time()
    parts = [
        chunk(1, bytes([2])), chunk(2, bytes([17])),
        chunk(3, socket.inet_aton(src_ip)), chunk(4, socket.inet_aton(dst_ip)),
        chunk(7, struct.pack('!H', 5060)), chunk(8, struct.pack('!H', 5060)),
        chunk(9, struct.pack('!I', int(now))), chunk(10, struct.pack('!I', int((now%1)*1e6))),
        chunk(11, bytes([1])), chunk(12, struct.pack('!I', 100)),
        chunk(0x11, cid.encode()), chunk(0x13, node.encode()),
        chunk(15, payload.encode()),
    ]
    body = b''.join(parts)
    return b'HEP3' + struct.pack('!H', 6+len(body)) + body

mps = $MPS
duration = $DURATION
port = $HEP_PORT
total = mps * duration

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent = 0
t_start = time.time()

for sec in range(duration):
    t_sec = time.time()
    for i in range(mps):
        cid = f'load-{sec}-{i}@bench'
        sip = f'OPTIONS sip:echo@10.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 10.{sec%256}.{i//256}.{i%256}:5060;branch=z9hG4bK-l{sec}{i}\r\nFrom: <sip:bench@load>;tag=l{sec}{i}\r\nTo: <sip:echo@10.0.0.1>\r\nCall-ID: {cid}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'
        pkt = hep3(sip, f'10.{sec%256}.{(i//256)%256}.{i%256}', '10.0.0.1', f'bench-{sec%10}', cid)
        s.sendto(pkt, ('127.0.0.1', port))
        sent += 1
    # Pace to target rate
    elapsed = time.time() - t_sec
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    sys.stderr.write(f'\r  {sent}/{total} ({sent*100//total}%)')
    sys.stderr.flush()

s.close()
elapsed = time.time() - t_start
sys.stderr.write(f'\r  sent {sent} in {elapsed:.1f}s = {sent/elapsed:.0f} msg/s\n')
" 2>&1

# Wait for DB writer to drain
echo "  Waiting for DB drain..."
sleep 3

T1=$(python3 -c 'import time;print(time.time())')
ELAPSED=$(python3 -c "print(f'{$T1 - $T0:.1f}')")

# Get results
AFTER=$(curl -s "http://127.0.0.1:${API_PORT}/api/health" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("captures",0))' 2>/dev/null || echo 0)
DB_ERR_AFTER=$(curl -s "http://127.0.0.1:${API_PORT}/api/health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["db"]["writes_err"])' 2>/dev/null || echo 0)
STORED=$((AFTER - BEFORE))
DB_ERRS=$((DB_ERR_AFTER - DB_ERR_BEFORE))
RATE=$(python3 -c "print(f'{$STORED / $ELAPSED:.0f}')" 2>/dev/null || echo "?")
LOSS=$((TOTAL - STORED))
LOSS_PCT=$(python3 -c "print(f'{$LOSS * 100 / $TOTAL:.1f}' if $TOTAL > 0 else '0')" 2>/dev/null)

echo ""
echo "Results"
echo "-------"
echo "  Sent:       ${TOTAL} messages"
echo "  Stored:     ${STORED} messages"
echo "  Lost:       ${LOSS} (${LOSS_PCT}%)"
echo "  DB errors:  ${DB_ERRS}"
echo "  Duration:   ${ELAPSED}s"
echo "  Throughput: ${RATE} msg/s (sustained write)"
echo ""

if [ "$LOSS" -gt $((TOTAL / 10)) ]; then
    echo "WARNING: >10% message loss — channel backpressure or DB too slow"
    exit 1
elif [ "$DB_ERRS" -gt 0 ]; then
    echo "WARNING: DB write errors detected"
    exit 1
else
    echo "LOAD TEST OK"
fi
