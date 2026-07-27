#!/usr/bin/env bash
# Start core + web for local demo (high ports, no root).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"

SIP="${ZAMAN_SIP_PORT:-15060}"
HEP="${ZAMAN_HEP_PORT:-19060}"
API="${ZAMAN_API_PORT:-19090}"
WEB="${ZAMAN_WEB_PORT:-3000}"

mkdir -p "${ROOT}/bin"
if [[ ! -x "${ROOT}/bin/zaman-core" ]]; then
  mako build --release "${ROOT}/core/main.mko" -o "${ROOT}/bin/zaman-core"
fi

# Demo enables probe for the UI form; never do this on a public interface.
ZAMAN_PROBE=1 "${ROOT}/bin/zaman-core" "$SIP" "$HEP" "$API" &
CORE_PID=$!

cleanup() {
  kill "$CORE_PID" "$WEB_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for i in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${API}/api/health" >/dev/null 2>&1 && break
  sleep 0.1
done

export ZAMAN_CORE="http://127.0.0.1:${API}"
weft run "${ROOT}/web/main.weft" &
WEB_PID=$!

echo ""
echo "Zaman demo"
echo "  dashboard  http://127.0.0.1:${WEB}"
echo "  core API   http://127.0.0.1:${API}/api/health"
echo "  SIP echo   udp/${SIP}"
echo "  HEP        udp/${HEP}"
echo "  Prometheus http://127.0.0.1:${API}/metrics"
echo ""
echo "Try: make smoke   or open the probe page and hit 127.0.0.1:${SIP}"
echo "Ctrl-C to stop."
wait
