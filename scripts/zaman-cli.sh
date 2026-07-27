#!/bin/bash
# zaman-cli — command-line interface for Zaman
# Usage:
#   zaman-cli search --call-id X
#   zaman-cli search --agent kamailio --method INVITE
#   zaman-cli export json --call-id X > calls.json
#   zaman-cli export csv --call-id X > calls.csv
#   zaman-cli export pcap --call-id X > call.pcap
#   zaman-cli health
#   zaman-cli kpi
#   zaman-cli nodes
#   zaman-cli calls --limit 20
#   zaman-cli ladder <call-id>
#   zaman-cli delete --call-id X (requires API key)
set -euo pipefail

CORE="${ZAMAN_CORE:-http://127.0.0.1:9090}"
KEY="${ZAMAN_API_KEY:-}"

auth_header() {
    if [ -n "$KEY" ]; then
        echo "-H" "X-API-Key: $KEY"
    fi
}

cmd="${1:-help}"
shift || true

case "$cmd" in
    health)
        curl -fsS $(auth_header) "$CORE/api/health" | python3 -m json.tool 2>/dev/null || \
            curl -fsS $(auth_header) "$CORE/api/health"
        ;;
    kpi)
        curl -fsS $(auth_header) "$CORE/api/report/kpi" | python3 -m json.tool 2>/dev/null || \
            curl -fsS $(auth_header) "$CORE/api/report/kpi"
        ;;
    nodes)
        curl -fsS $(auth_header) "$CORE/api/nodes" | python3 -m json.tool 2>/dev/null || \
            curl -fsS $(auth_header) "$CORE/api/nodes"
        ;;
    calls)
        limit="${2:-20}"
        curl -fsS $(auth_header) "$CORE/api/report/top-calls?limit=$limit" | \
            python3 -c "
import sys,json
for c in json.load(sys.stdin):
    print(f'{c[\"messages\"]:4d} msgs  {c[\"call_id\"]}')
" 2>/dev/null || curl -fsS $(auth_header) "$CORE/api/report/top-calls?limit=$limit"
        ;;
    search)
        qs=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --call-id) qs="${qs}&call_id=$2"; shift 2 ;;
                --agent) qs="${qs}&agent=$2"; shift 2 ;;
                --method) qs="${qs}&method=$2"; shift 2 ;;
                --transport) qs="${qs}&transport=$2"; shift 2 ;;
                --src) qs="${qs}&src=$2"; shift 2 ;;
                --limit) qs="${qs}&limit=$2"; shift 2 ;;
                *) echo "unknown: $1"; exit 1 ;;
            esac
        done
        curl -fsS $(auth_header) "$CORE/api/messages?${qs#&}" | \
            python3 -c "
import sys,json
for m in json.load(sys.stdin):
    cid = m.get('call_id','')[:30]
    print(f'{m[\"id\"]:5d}  {m.get(\"method\",\"\"):10s} {m.get(\"status\",0):3d}  {m.get(\"src\",\"\"):22s} → {m.get(\"dst\",\"\"):22s}  {m.get(\"transport\",\"\"):10s} {cid}')
" 2>/dev/null || curl -fsS $(auth_header) "$CORE/api/messages?${qs#&}"
        ;;
    export)
        fmt="${1:-json}"; shift || true
        qs=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --call-id) qs="${qs}&call_id=$2"; shift 2 ;;
                --agent) qs="${qs}&agent=$2"; shift 2 ;;
                --method) qs="${qs}&method=$2"; shift 2 ;;
                --limit) qs="${qs}&limit=$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        case "$fmt" in
            json) curl -fsS $(auth_header) "$CORE/api/export?${qs#&}" ;;
            csv)
                curl -fsS $(auth_header) "$CORE/api/export?${qs#&}" | python3 -c "
import sys,json,csv,io
msgs = json.load(sys.stdin)
if not msgs: sys.exit(0)
w = csv.DictWriter(sys.stdout, fieldnames=['id','ts_ms','src','dst','transport','proto','agent','kind','method','status','call_id','from','to','cseq','ruri'])
w.writeheader()
for m in msgs: w.writerow({k:m.get(k,'') for k in w.fieldnames})
" ;;
            pcap)
                curl -fsS $(auth_header) "$CORE/api/export?${qs#&}" | \
                    python3 "$(dirname "$0")/gen_pcap.py"
                ;;
            *) echo "formats: json, csv, pcap"; exit 1 ;;
        esac
        ;;
    ladder)
        cid="${1:?usage: zaman-cli ladder <call-id>}"
        curl -fsS $(auth_header) "$CORE/api/messages?call_id=$cid&limit=200" | python3 -c "
import sys,json
msgs = sorted(json.load(sys.stdin), key=lambda m: m.get('ts_ms',0))
if not msgs: print('No messages.'); sys.exit(0)
endpoints = []
for m in msgs:
    for ep in [m.get('src',''), m.get('dst','')]:
        if ep and ep not in endpoints: endpoints.append(ep)
width = max(len(e) for e in endpoints) if endpoints else 10
print('  '.join(e.center(width) for e in endpoints))
print('  '.join('-'*width for _ in endpoints))
for m in msgs:
    src = m.get('src','')
    dst = m.get('dst','')
    method = m.get('method','')
    status = m.get('status',0)
    kind = m.get('kind','')
    label = f'{status} {method}' if kind == 'response' else method
    si = endpoints.index(src) if src in endpoints else 0
    di = endpoints.index(dst) if dst in endpoints else si
    if si == di:
        cols = ['  '*width]*len(endpoints)
        cols[si] = f'[{label}]'.center(width)
    elif si < di:
        cols = ['  '*width]*len(endpoints)
        cols[si] = '|'.ljust(width)
        cols[di] = '|'.ljust(width)
        arrow = f'---{label}--->'
        mid = (si + di) // 2
        cols[mid] = arrow.center(width)
    else:
        cols = ['  '*width]*len(endpoints)
        cols[si] = '|'.ljust(width)
        cols[di] = '|'.ljust(width)
        arrow = f'<---{label}---'
        mid = (di + si) // 2
        cols[mid] = arrow.center(width)
    print('  '.join(cols))
" 2>/dev/null || echo "install python3 for ladder view"
        ;;
    anomalies)
        curl -fsS $(auth_header) "$CORE/api/anomalies" | python3 -m json.tool 2>/dev/null || \
            curl -fsS $(auth_header) "$CORE/api/anomalies"
        ;;
    *)
        cat <<EOF
zaman-cli — Zaman command-line interface

Commands:
  health                    Deep health check
  kpi                       Telecom KPIs (ASR, NER, etc.)
  nodes                     HEP agent status
  calls [--limit N]         Top Call-IDs
  anomalies                 Active anomaly indicators
  search [filters]          Search messages
    --call-id X             Filter by Call-ID
    --agent X               Filter by HEP agent
    --method INVITE         Filter by SIP method
    --transport HEP3        Filter by transport
    --src 10.0.1            Filter by endpoint IP
    --limit N               Max results (default 50)
  ladder <call-id>          ASCII call ladder
  export json|csv|pcap [filters]
                            Export captures

Environment:
  ZAMAN_CORE    Core URL (default: http://127.0.0.1:9090)
  ZAMAN_API_KEY API key for authenticated endpoints
EOF
        ;;
esac
