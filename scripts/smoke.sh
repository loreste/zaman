#!/usr/bin/env bash
# End-to-end smoke: SIP echo + HEP UDP/TCP/TLS + probe + metrics
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
cd "$ROOT"
mkdir -p data

if [[ ! -x ./bin/zaman-core ]]; then
  mako build --release core/main.mko -o bin/zaman-core
fi

pkill -x zaman-core 2>/dev/null || true
sleep 0.5

PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do
    kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_health() {
  local port=$1 pid=$2
  local i
  for i in $(seq 1 80); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "core pid $pid died before health on :$port"
      return 1
    fi
    if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timeout health :$port"
  return 1
}

echo "== start core =="
: > data/smoke-core.log
nohup env ZAMAN_PROBE=1 ZAMAN_HEP_TCP=0 ./bin/zaman-core 15060 19060 19090 \
  >>data/smoke-core.log 2>&1 &
PID=$!
PIDS+=("$PID")
sleep 0.8
wait_health 19090 "$PID" || { cat data/smoke-core.log; exit 1; }

echo "== health =="
curl -fsS "http://127.0.0.1:19090/api/health"; echo

echo "== OPTIONS echo =="
python3 - <<'PY'
import socket, sys, time
msg = (
"OPTIONS sip:echo@127.0.0.1:15060 SIP/2.0\r\n"
"Via: SIP/2.0/UDP 127.0.0.1:45060;branch=z9hG4bK-smoke;rport\r\n"
"From: <sip:smoke@local>;tag=s1\r\n"
"To: <sip:echo@127.0.0.1>\r\n"
f"Call-ID: smoke-{int(time.time())}@local\r\n"
"CSeq: 1 OPTIONS\r\n"
"Max-Forwards: 70\r\n"
"Content-Length: 0\r\n"
"\r\n"
)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(msg.encode(), ("127.0.0.1", 15060))
data, _ = s.recvfrom(65535)
line = data.decode(errors="replace").splitlines()[0]
print(line)
sys.exit(0 if "200" in line else 1)
PY

echo "== probe =="
curl -fsS -X POST -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1","port":15060,"timeout_ms":1500}' \
  "http://127.0.0.1:19090/api/probe"
echo

echo "== HEP3 UDP =="
CID="hep-smoke-$(date +%s)@local"
python3 scripts/send_hep.py --host 127.0.0.1 --port 19060 \
  --node-id 42 --node-name smoke-agent --src 10.9.8.7 --dst 10.1.1.1 --call-id "$CID"
sleep 0.3
HEPJ=$(curl -fsS "http://127.0.0.1:19090/api/messages?limit=20&call_id=${CID}")
echo "$HEPJ" | head -c 400; echo
echo "$HEPJ" | grep -q "HEP3" || { echo "HEP UDP fail"; exit 1; }
echo "HEP UDP OK"

echo "== metrics =="
curl -fsS "http://127.0.0.1:19090/api/metrics" | head -c 300; echo
curl -fsS "http://127.0.0.1:19090/metrics" | head -12; echo

echo "== HEP3 TCP =="
: > data/smoke-tcp.log
nohup env ZAMAN_PROBE=0 ZAMAN_HEP_TCP=1 ZAMAN_HEP_TCP_PORT=19062 \
  ./bin/zaman-core 15061 19061 19091 >>data/smoke-tcp.log 2>&1 &
TCP_PID=$!
PIDS+=("$TCP_PID")
sleep 0.8
wait_health 19091 "$TCP_PID" || { cat data/smoke-tcp.log; exit 1; }
CIDT="hep-tcp-$(date +%s)@local"
python3 scripts/send_hep.py --tcp --host 127.0.0.1 --port 19062 \
  --node-name smoke-tcp --call-id "$CIDT" --count 2
sleep 0.4
HEPT=$(curl -fsS "http://127.0.0.1:19091/api/messages?limit=20&call_id=${CIDT}-0")
echo "$HEPT" | head -c 400; echo
echo "$HEPT" | grep -q "HEP3/TCP" || { echo "HEP TCP fail: $HEPT"; exit 1; }
MET=$(curl -fsS "http://127.0.0.1:19091/api/metrics")
echo "$MET" | grep -q '"hep_tcp":[1-9]' || { echo "hep_tcp counter fail: $MET"; exit 1; }
kill "$TCP_PID" 2>/dev/null || true
wait "$TCP_PID" 2>/dev/null || true
echo "HEP TCP OK"

echo "== HEP3 TLS =="
CERT_DIR=data/tls
mkdir -p "$CERT_DIR"
if [[ ! -f "$CERT_DIR/hep.crt" || ! -f "$CERT_DIR/hep.key" ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/hep.key" -out "$CERT_DIR/hep.crt" \
    -days 2 -nodes -subj "/CN=localhost" 2>/dev/null
fi
: > data/smoke-tls.log
nohup env ZAMAN_HEP_TCP=0 ZAMAN_HEP_TLS=1 \
  ZAMAN_HEP_TLS_CERT="$CERT_DIR/hep.crt" \
  ZAMAN_HEP_TLS_KEY="$CERT_DIR/hep.key" \
  ZAMAN_HEP_TLS_PORT=19063 \
  ./bin/zaman-core 15063 19064 19093 >>data/smoke-tls.log 2>&1 &
TLS_PID=$!
PIDS+=("$TLS_PID")
sleep 0.8
wait_health 19093 "$TLS_PID" || { cat data/smoke-tls.log; exit 1; }
CIDL="hep-tls-$(date +%s)@local"
python3 scripts/send_hep.py --tls --insecure --host 127.0.0.1 --port 19063 \
  --node-name smoke-tls --call-id "$CIDL"
sleep 0.5
HEPL=$(curl -fsS "http://127.0.0.1:19093/api/messages?limit=10&call_id=${CIDL}")
echo "$HEPL" | head -c 400; echo
echo "$HEPL" | grep -q "HEP3/TLS" || { echo "HEP TLS fail: $HEPL"; exit 1; }
echo "HEP TLS OK"

echo "== messages =="
curl -fsS "http://127.0.0.1:19090/api/messages?limit=3" | head -c 400; echo

echo "SMOKE OK"
