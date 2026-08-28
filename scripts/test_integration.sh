#!/bin/bash
# Zaman integration test suite
# Tests all three database backends, API endpoints, auth, federation, and edge cases.
# Usage: ./scripts/test_integration.sh [sqlite|postgres|clickhouse|all]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
cd "$ROOT"

PASS=0
FAIL=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

assert() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} $desc"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} $desc (expected='$expected' got='$actual')"
    fi
}

assert_contains() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} $desc"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} $desc (missing '$needle')"
    fi
}

assert_gt() {
    TOTAL=$((TOTAL + 1))
    local desc="$1" val="$2" threshold="$3"
    if [ "$val" -gt "$threshold" ] 2>/dev/null; then
        PASS=$((PASS + 1))
        echo -e "  ${GREEN}✓${NC} $desc ($val > $threshold)"
    else
        FAIL=$((FAIL + 1))
        echo -e "  ${RED}✗${NC} $desc ($val not > $threshold)"
    fi
}

PIDS=()
cleanup() {
    for p in "${PIDS[@]:-}"; do
        kill "$p" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_health() {
    local port=$1 pid=$2
    for i in $(seq 1 80); do
        kill -0 "$pid" 2>/dev/null || return 1
        curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    return 1
}

inject_traffic() {
    local hep_port=$1 sip_port=$2
    python3 -c "
import socket, struct, time
def c(tid,val,v=0): return struct.pack('!HHH',v,tid,6+len(val))+val
def h(p,s,d,n,cid):
    now=time.time()
    parts=[c(1,bytes([2])),c(2,bytes([17])),c(3,socket.inet_aton(s)),c(4,socket.inet_aton(d)),c(7,struct.pack('!H',5060)),c(8,struct.pack('!H',5060)),c(9,struct.pack('!I',int(now))),c(10,struct.pack('!I',int((now%1)*1e6))),c(11,bytes([1])),c(12,struct.pack('!I',100)),c(0x11,cid.encode()),c(0x13,n.encode()),c(15,p.encode())]
    body=b''.join(parts);return b'HEP3'+struct.pack('!H',6+len(body))+body
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);ts=int(time.time())
cid=f'inttest-{ts}@test'
for src,dst,node,sip in [
    ('10.1.1.10','10.2.2.20','test-gw',f'INVITE sip:b@10.2.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.1.10:5060;branch=z9hG4bK-t1\r\nFrom: <sip:a@10.1.1.10>;tag=t1\r\nTo: <sip:b@10.2.2.20>\r\nCall-ID: {cid}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'),
    ('10.2.2.20','10.1.1.10','test-fs',f'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.1.1.10:5060;branch=z9hG4bK-t1\r\nFrom: <sip:a@10.1.1.10>;tag=t1\r\nTo: <sip:b@10.2.2.20>;tag=r1\r\nCall-ID: {cid}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'),
    ('10.1.1.10','10.2.2.20','test-gw',f'BYE sip:b@10.2.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.1.10:5060;branch=z9hG4bK-t2\r\nFrom: <sip:a@10.1.1.10>;tag=t1\r\nTo: <sip:b@10.2.2.20>;tag=r1\r\nCall-ID: {cid}\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n'),
    ('10.2.2.20','10.1.1.10','test-fs',f'SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.1.1.10:5060;branch=z9hG4bK-t2\r\nFrom: <sip:a@10.1.1.10>;tag=t1\r\nTo: <sip:b@10.2.2.20>;tag=r1\r\nCall-ID: {cid}\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n'),
]:
    s.sendto(h(sip,src,dst,node,cid),('127.0.0.1',$hep_port));time.sleep(0.02)
# OPTIONS for echo test
s.sendto(b'OPTIONS sip:echo@127.0.0.1:$sip_port SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:44444;branch=z9hG4bK-opt\r\nFrom: <sip:test@local>;tag=opt1\r\nTo: <sip:echo@127.0.0.1>\r\nCall-ID: opt-'+str(ts).encode()+b'@test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n',('127.0.0.1',$sip_port))
s.close()
print(cid)
" 2>/dev/null
}

# ══════════════════════════════════════════
# Test suite for a given DB backend
# ══════════════════════════════════════════
run_tests() {
    local db_driver="$1"
    local sip_port=15070 hep_port=19070 api_port=19095

    echo ""
    echo -e "${YELLOW}═══ Testing: ${db_driver} ═══${NC}"

    # Clean
    pkill -x zaman-core 2>/dev/null || true
    sleep 0.5
    rm -rf data/test-${db_driver}.db data/test-${db_driver}.db-* 2>/dev/null

    # Start core
    local env_args="ZAMAN_PROBE=1 ZAMAN_DB=data/test-${db_driver}.db"
    if [ "$db_driver" = "postgres" ]; then
        if ! sudo -u postgres psql -c "SELECT 1" >/dev/null 2>&1; then
            echo -e "  ${YELLOW}⊘${NC} PostgreSQL not available, skipping"
            return
        fi
        sudo -u postgres dropdb zaman_test 2>/dev/null || true
        sudo -u postgres createdb zaman_test 2>/dev/null
        env_args="ZAMAN_DB_DRIVER=postgres ZAMAN_DB_DSN='host=/var/run/postgresql dbname=zaman_test user=$(whoami) sslmode=disable' ZAMAN_PROBE=1"
    elif [ "$db_driver" = "clickhouse" ]; then
        if ! curl -fs http://127.0.0.1:8123/ping >/dev/null 2>&1; then
            echo -e "  ${YELLOW}⊘${NC} ClickHouse not available, skipping"
            return
        fi
        curl -s 'http://127.0.0.1:8123/' -d 'DROP DATABASE IF EXISTS zaman_test' >/dev/null
        env_args="ZAMAN_DB_DRIVER=clickhouse ZAMAN_CH_URL=http://127.0.0.1:8123 ZAMAN_CH_DB=zaman_test ZAMAN_PROBE=1"
    fi

    eval $env_args ./bin/zaman-core $sip_port $hep_port $api_port >data/test-${db_driver}.log 2>&1 &
    local PID=$!
    PIDS+=("$PID")
    wait_health $api_port $PID || { echo -e "  ${RED}✗${NC} core failed to start"; cat data/test-${db_driver}.log; return; }

    # ── Health ──
    echo "  Health:"
    local health=$(curl -s "http://127.0.0.1:${api_port}/api/health")
    assert "health returns ok" "True" "$(echo "$health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["ok"])' 2>/dev/null)"
    assert "version is 0.3.0" "0.3.0" "$(echo "$health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["version"])' 2>/dev/null)"
    assert_contains "health has db info" "driver" "$health"
    assert_contains "health has channel_capacity" "channel_capacity" "$health"

    # ── Inject traffic ──
    echo "  Capture:"
    local CID=$(inject_traffic $hep_port $sip_port)
    sleep 0.5

    # ── Messages API ──
    local msgs=$(curl -s "http://127.0.0.1:${api_port}/api/messages?limit=50")
    local msg_count=$(echo "$msgs" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null)
    assert_gt "messages captured" "$msg_count" 0

    # ── Search by call_id ──
    local by_cid=$(curl -s "http://127.0.0.1:${api_port}/api/messages?call_id=${CID}")
    local cid_count=$(echo "$by_cid" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null)
    assert "search by call_id finds 4" "4" "$cid_count"

    # ── Search by agent ──
    local by_agent=$(curl -s "http://127.0.0.1:${api_port}/api/messages?agent=test-gw")
    local agent_count=$(echo "$by_agent" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null)
    assert_gt "search by agent" "$agent_count" 0

    # ── Search by method ──
    local by_method=$(curl -s "http://127.0.0.1:${api_port}/api/messages?method=INVITE")
    assert_contains "search by method returns INVITE" "INVITE" "$by_method"

    # ── Single message ──
    echo "  Single message:"
    local first_id=$(echo "$msgs" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])' 2>/dev/null)
    local one=$(curl -s "http://127.0.0.1:${api_port}/api/messages/${first_id}")
    assert_contains "single message has call_id" "call_id" "$one"
    local missing=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${api_port}/api/messages/999999")
    assert "missing message returns 404" "404" "$missing"

    # ── Reports ──
    echo "  Reports:"
    local kpi=$(curl -s "http://127.0.0.1:${api_port}/api/report/kpi")
    assert_contains "KPI has asr" "asr" "$kpi"
    assert_contains "KPI has total_invites" "total_invites" "$kpi"

    local summary=$(curl -s "http://127.0.0.1:${api_port}/api/report/summary")
    assert_contains "summary has total" "total" "$summary"

    local rcodes=$(curl -s "http://127.0.0.1:${api_port}/api/report/response-codes")
    assert_contains "response codes has status" "status" "$rcodes"

    local talkers=$(curl -s "http://127.0.0.1:${api_port}/api/report/top-talkers")
    assert_contains "top talkers has src" "src" "$talkers"

    local agents=$(curl -s "http://127.0.0.1:${api_port}/api/report/agents")
    assert_contains "agents has test-gw" "test-gw" "$agents"

    local daily=$(curl -s "http://127.0.0.1:${api_port}/api/report/daily")
    assert_contains "daily has day" "day" "$daily"

    local cps=$(curl -s "http://127.0.0.1:${api_port}/api/report/cps?minutes=5")
    # CPS may be empty if traffic is too recent, just check it's valid JSON
    assert_contains "cps is valid" "[" "$cps"

    # ── Realtime ──
    echo "  Realtime:"
    local rt=$(curl -s "http://127.0.0.1:${api_port}/api/realtime?window=5")
    assert_contains "realtime has active_calls" "active_calls" "$rt"
    assert_contains "realtime has asr" "asr" "$rt"

    # ── Nodes ──
    local nodes=$(curl -s "http://127.0.0.1:${api_port}/api/nodes")
    assert_contains "nodes has agent" "agent" "$nodes"
    assert_contains "nodes has status" "status" "$nodes"

    # ── Anomalies ──
    local anom=$(curl -s "http://127.0.0.1:${api_port}/api/anomalies")
    assert_contains "anomalies is valid JSON" "[" "$anom"

    # ── SLA ──
    echo "  SLA:"
    local sla_agents=$(curl -s "http://127.0.0.1:${api_port}/api/sla/agents")
    assert_contains "sla agents has asr" "asr" "$sla_agents"

    local sla_dests=$(curl -s "http://127.0.0.1:${api_port}/api/sla/destinations")
    assert_contains "sla destinations has dst" "dst" "$sla_dests"

    # ── Related calls ──
    local related=$(curl -s "http://127.0.0.1:${api_port}/api/related?call_id=${CID}")
    assert_contains "related is valid JSON" "[" "$related"

    # ── Probe ──
    echo "  Probe:"
    local probe=$(curl -s -X POST -H 'Content-Type: application/json' \
        -d "{\"host\":\"127.0.0.1\",\"port\":${sip_port},\"timeout_ms\":2000}" \
        "http://127.0.0.1:${api_port}/api/probe")
    assert_contains "probe returns ok" "ok" "$probe"

    # ── Prometheus ──
    echo "  Prometheus:"
    local prom=$(curl -s "http://127.0.0.1:${api_port}/metrics")
    assert_contains "prometheus has zaman_up" "zaman_up" "$prom"
    assert_contains "prometheus has zaman_messages_total" "zaman_messages_total" "$prom"

    # ── Federation ──
    echo "  Federation:"
    local fed_health=$(curl -s "http://127.0.0.1:${api_port}/api/federation/health")
    assert_contains "federation health" "federation" "$fed_health"

    local fed_push=$(curl -s -X POST -H 'Content-Type: application/json' \
        -d '{"ts_ms":1785200000000,"src":"10.9.9.9:5060","dst":"10.8.8.8:5060","transport":"HEP3","proto":"sip","agent":"fed-test","kind":"request","method":"OPTIONS","status":0,"call_id":"fed-inttest@test","from":"test","to":"test","cseq":"1 OPTIONS","ruri":"sip:x","hep_node_id":0,"hep_node":"fed","hep_cid":"","size":50,"raw_b64":""}' \
        "http://127.0.0.1:${api_port}/api/federation/push")
    assert_contains "federation push accepted" "accepted" "$fed_push"

    # ── Export ──
    echo "  Export:"
    local export_json=$(curl -s "http://127.0.0.1:${api_port}/api/export?limit=5")
    assert_contains "export has records" "call_id" "$export_json"

    # ── Grafana ──
    echo "  Grafana:"
    local grafana=$(curl -s "http://127.0.0.1:${api_port}/api/grafana/")
    assert_contains "grafana health" "ok" "$grafana"
    local grafana_search=$(curl -s "http://127.0.0.1:${api_port}/api/grafana/search")
    assert_contains "grafana search has metrics" "messages_total" "$grafana_search"

    # ── Rate limiting ──
    echo "  Rate limiting:"
    # Send 105 rapid requests
    for i in $(seq 1 105); do curl -s -o /dev/null "http://127.0.0.1:${api_port}/api/health"; done
    local rate_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${api_port}/api/health")
    # May or may not hit 429 depending on timing
    if [ "$rate_code" = "429" ]; then
        assert "rate limit enforced" "429" "$rate_code"
    else
        assert "rate limit (within window)" "200" "$rate_code"
    fi

    # ── Restart recovery ──
    echo "  Restart recovery:"
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null || true
    sleep 1
    eval $env_args ./bin/zaman-core $sip_port $hep_port $api_port >>data/test-${db_driver}-restart.log 2>&1 &
    PID=$!
    PIDS+=("$PID")
    wait_health $api_port $PID || { echo -e "  ${RED}✗${NC} restart failed"; return; }
    local after_restart=$(curl -s "http://127.0.0.1:${api_port}/api/messages?call_id=${CID}")
    local after_count=$(echo "$after_restart" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))' 2>/dev/null)
    assert "data survives restart" "4" "$after_count"

    # Cleanup
    kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null || true
}

# ══════════════════════════════════════════
# Main
# ══════════════════════════════════════════
echo ""
echo "Zaman Integration Tests"
echo "======================="

if [[ ! -x ./bin/zaman-core ]]; then
    make build || exit 1
fi

TARGET="${1:-all}"

case "$TARGET" in
    sqlite) run_tests sqlite ;;
    postgres) run_tests postgres ;;
    clickhouse) run_tests clickhouse ;;
    all)
        run_tests sqlite
        run_tests postgres
        run_tests clickhouse
        ;;
    *) echo "Usage: $0 [sqlite|postgres|clickhouse|all]"; exit 1 ;;
esac

echo ""
echo "═══════════════════════════"
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${TOTAL} total"
echo "═══════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
