#!/usr/bin/env python3
"""Generate a PCAP file from Zaman JSON messages. Usage:
  curl -s 'http://127.0.0.1:9090/api/messages?call_id=X&limit=200' | python3 scripts/gen_pcap.py > call.pcap
  python3 scripts/gen_pcap.py --core http://127.0.0.1:9090 --call-id X -o call.pcap
"""
import argparse, base64, json, socket, struct, sys, urllib.request

def ip_to_bytes(ip):
    try:
        return socket.inet_aton(ip)
    except Exception:
        return b'\x00\x00\x00\x00'

def parse_endpoint(s):
    if not s or ':' not in s:
        return '0.0.0.0', 5060
    parts = s.rsplit(':', 1)
    try:
        return parts[0], int(parts[1])
    except ValueError:
        return parts[0], 5060

def build_pcap(messages):
    # Global header: magic, v2.4, snaplen=65535, linktype=101 (LINKTYPE_RAW)
    out = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
    for m in messages:
        raw = base64.b64decode(m.get('raw_b64', ''))
        if not raw:
            continue
        ts_ms = m.get('ts_ms', 0)
        src_ip, src_port = parse_endpoint(m.get('src', ''))
        dst_ip, dst_port = parse_endpoint(m.get('dst', m.get('src', '')))
        # UDP header
        udp_len = 8 + len(raw)
        udp = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
        # IP header (v4, UDP=17)
        ip_len = 20 + udp_len
        ip_hdr = struct.pack('!BBHHHBBH', 0x45, 0, ip_len, 0, 0, 64, 17, 0)
        ip_hdr += ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)
        pkt = ip_hdr + udp + raw
        # Packet header
        ts_sec = ts_ms // 1000
        ts_usec = (ts_ms % 1000) * 1000
        out += struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt))
        out += pkt
    return out

def main():
    p = argparse.ArgumentParser(description='Generate PCAP from Zaman captures')
    p.add_argument('--core', default='http://127.0.0.1:9090')
    p.add_argument('--call-id', default='')
    p.add_argument('--limit', type=int, default=200)
    p.add_argument('-o', '--output', default='')
    p.add_argument('--api-key', default='')
    args = p.parse_args()

    if not sys.stdin.isatty():
        messages = json.load(sys.stdin)
    elif args.call_id:
        url = f"{args.core}/api/messages?limit={args.limit}&call_id={args.call_id}"
        req = urllib.request.Request(url)
        if args.api_key:
            req.add_header('X-API-Key', args.api_key)
        messages = json.loads(urllib.request.urlopen(req).read())
    else:
        p.error('Provide --call-id or pipe JSON on stdin')

    # Reverse to chronological
    messages.sort(key=lambda m: m.get('ts_ms', 0))
    pcap = build_pcap(messages)

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(pcap)
        print(f'Wrote {len(messages)} packets to {args.output}', file=sys.stderr)
    else:
        sys.stdout.buffer.write(pcap)

if __name__ == '__main__':
    main()
