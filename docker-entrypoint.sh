#!/bin/sh
set -e

SIP_PORT="${ZAMAN_SIP_PORT:-5060}"
HEP_PORT="${ZAMAN_HEP_PORT:-9060}"
API_PORT="${ZAMAN_API_PORT:-9090}"

# Start core in background
/app/bin/zaman-core "$SIP_PORT" "$HEP_PORT" "$API_PORT" &
CORE_PID=$!

# Wait for core health
for i in $(seq 1 60); do
    curl -fs "http://127.0.0.1:${API_PORT}/api/health" >/dev/null 2>&1 && break
    sleep 0.5
done

# Start dashboard in foreground
exec weft run /app/web/main.weft
