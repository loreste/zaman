#!/usr/bin/env python3
"""Send a SIP OPTIONS and print the response. Usage: send_options.py [host] [port]"""
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
cid = f"cli-{int(time.time())}@local"
msg = (
    f"OPTIONS sip:echo@{host}:{port} SIP/2.0\r\n"
    f"Via: SIP/2.0/UDP 127.0.0.1:45060;branch=z9hG4bK-cli;rport\r\n"
    f"From: <sip:cli@local>;tag=cli1\r\n"
    f"To: <sip:echo@{host}>\r\n"
    f"Call-ID: {cid}\r\n"
    f"CSeq: 1 OPTIONS\r\n"
    f"Max-Forwards: 70\r\n"
    f"Content-Length: 0\r\n"
    f"\r\n"
)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(msg.encode(), (host, port))
data, addr = s.recvfrom(65535)
print(f"from {addr}")
print(data.decode(errors="replace"))
