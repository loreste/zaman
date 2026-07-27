#!/usr/bin/env python3
"""Send a HEPv3 (EEP) packet with a SIP OPTIONS payload to Zaman.

Transports: UDP (default), TCP (length-framed stream), TLS.

Usage:
  send_hep.py --port 9060
  send_hep.py --tcp --port 9060
  send_hep.py --tls --port 9061 --insecure
"""
from __future__ import annotations

import argparse
import socket
import ssl
import struct
import time


def chunk(type_id: int, value: bytes, vendor: int = 0) -> bytes:
    return struct.pack("!HHH", vendor, type_id, 6 + len(value)) + value


def encode_hep3(
    payload: bytes,
    *,
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    src_port: int = 5060,
    dst_port: int = 5060,
    node_id: int = 2001,
    password: str = "",
    node_name: str = "zaman-test-agent",
    proto_type: int = 1,
    ip_proto: int = 17,
    correlation_id: str = "",
) -> bytes:
    now = time.time()
    tsec = int(now)
    tusec = int((now - tsec) * 1_000_000)

    parts = [
        chunk(0x0001, bytes([0x02])),
        chunk(0x0002, bytes([ip_proto])),
        chunk(0x0003, socket.inet_aton(src_ip)),
        chunk(0x0004, socket.inet_aton(dst_ip)),
        chunk(0x0007, struct.pack("!H", src_port)),
        chunk(0x0008, struct.pack("!H", dst_port)),
        chunk(0x0009, struct.pack("!I", tsec)),
        chunk(0x000A, struct.pack("!I", tusec)),
        chunk(0x000B, bytes([proto_type])),
        chunk(0x000C, struct.pack("!I", node_id)),
    ]
    if password:
        parts.append(chunk(0x000E, password.encode()))
    if correlation_id:
        parts.append(chunk(0x0011, correlation_id.encode()))
    if node_name:
        parts.append(chunk(0x0013, node_name.encode()))
    parts.append(chunk(0x000F, payload))

    body = b"".join(parts)
    total = 6 + len(body)
    return b"HEP3" + struct.pack("!H", total) + body


def default_sip(call_id: str, src_ip: str, dst_ip: str) -> bytes:
    return (
        f"OPTIONS sip:echo@{dst_ip} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src_ip}:5060;branch=z9hG4bK-hep-test;rport\r\n"
        f"From: <sip:hep@{src_ip}>;tag=heptag1\r\n"
        f"To: <sip:echo@{dst_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"Max-Forwards: 70\r\n"
        f"User-Agent: zaman-send-hep\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode()


def send_udp(host: str, port: int, pkt: bytes) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (host, port))
    s.close()


def send_tcp(host: str, port: int, pkt: bytes) -> None:
    s = socket.create_connection((host, port), timeout=5)
    try:
        s.sendall(pkt)
    finally:
        s.close()


def send_tls(host: str, port: int, pkt: bytes, insecure: bool) -> None:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=5)
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as ssock:
            ssock.sendall(pkt)
    finally:
        raw.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Send HEPv3 SIP capture to Zaman")
    p.add_argument("--host", default="127.0.0.1", help="HEP collector host")
    p.add_argument("--port", type=int, default=9060, help="HEP collector port")
    p.add_argument("--tcp", action="store_true", help="Send over TCP (framed stream)")
    p.add_argument("--tls", action="store_true", help="Send over TLS")
    p.add_argument("--insecure", action="store_true", help="TLS: skip cert verify (lab)")
    p.add_argument("--node-id", type=int, default=2001)
    p.add_argument("--password", default="", help="HEP node password chunk")
    p.add_argument("--node-name", default="zaman-test-agent")
    p.add_argument("--src", default="10.1.2.3")
    p.add_argument("--dst", default="10.4.5.6")
    p.add_argument("--sport", type=int, default=5060)
    p.add_argument("--dport", type=int, default=5060)
    p.add_argument("--call-id", default="")
    p.add_argument("--payload-file", default="", help="raw SIP file instead of built-in OPTIONS")
    p.add_argument("--count", type=int, default=1, help="send N frames (TCP/TLS stream)")
    args = p.parse_args()

    cid = args.call_id or f"hep-{int(time.time())}@zaman-test"
    if args.payload_file:
        with open(args.payload_file, "rb") as f:
            payload = f.read()
    else:
        payload = default_sip(cid, args.src, args.dst)

    frames = []
    for i in range(max(1, args.count)):
        c = cid if args.count == 1 else f"{cid}-{i}"
        pl = payload if args.count == 1 else default_sip(c, args.src, args.dst)
        frames.append(
            encode_hep3(
                pl,
                src_ip=args.src,
                dst_ip=args.dst,
                src_port=args.sport,
                dst_port=args.dport,
                node_id=args.node_id,
                password=args.password,
                node_name=args.node_name,
                correlation_id=c,
            )
        )
    blob = b"".join(frames)

    if args.tls:
        send_tls(args.host, args.port, blob, args.insecure)
        mode = "TLS"
    elif args.tcp:
        send_tcp(args.host, args.port, blob)
        mode = "TCP"
    else:
        send_udp(args.host, args.port, frames[0] if args.count == 1 else blob)
        # UDP: one datagram per frame
        if args.count > 1:
            for fr in frames[1:]:
                send_udp(args.host, args.port, fr)
        mode = "UDP"

    print(f"sent HEPv3/{mode} {len(blob)} bytes ({args.count} frame(s)) → {args.host}:{args.port} call-id={cid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
