#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import argparse
import socket
import ssl
import sys
from importlib.metadata import version

def debug(msg):
    if args.debug:
        print(msg)

def main():
    print("test")

print(f"xython-tlsd {version('xython')}")

parser = argparse.ArgumentParser()
parser.add_argument("--debug", "-d", help="increase debug level", action="store_true")
parser.add_argument("--netport", help="Network port", default=1985)
parser.add_argument("--logdir", help="Override xython log directory", default="/var/log/xython/")
parser.add_argument("--etcdir", help="Override xython etc directory", default="/etc/xython/")
parser.add_argument("--tlskey", help="Override xython TLS key")
parser.add_argument("--tlscrt", help="Override xython TLS certificate")
parser.add_argument("--quit", help="Quit after x seconds", type=int, default=0)
parser.add_argument("--xythonsock", help="Override xython socker patch", default="/run/xython/xython.sock")
args = parser.parse_args()

XYTHON_SOCK=args.xythonsock
TLS_KEY = None
TLS_CRT = None
HOST = "0.0.0.0"

f = open(f"{args.etcdir}/xython.cfg", 'r')
for line in f:
    line = line.rstrip()
    tokens = line.split('=')
    keyword = tokens[0]
    if keyword == 'XYTHON_TLS_KEY':
        TLS_KEY = tokens[1]
        debug(f"TLS_KEY is now {TLS_KEY}")
    if keyword == 'XYTHON_TLS_CRT':
        TLS_CRT = tokens[1]
        debug(f"TLS_CRT is now {TLS_CRT}")

if args.tlscrt is not None:
    TLS_CRT = args.tlscrt
if args.tlskey is not None:
    TLS_KEY = args.tlskey

if TLS_CRT is None:
    print("ERROR: missing certificate file")
    sys.exit(1)

if TLS_KEY is None:
    print("ERROR: missing key file")
    sys.exit(1)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(TLS_CRT, TLS_KEY)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    # TODO ipv6
    sock.bind(('0.0.0.0', int(args.netport)))
    sock.listen(100)
    if args.quit > 0:
        sys.exit(0)
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            conn.settimeout(2)
            ipaddr = addr[0]
            debug(f"Got connection from {ipaddr}")
            total = b""
            theend = False
            while not theend:
                try:
                    data = conn.recv(64384)
                    debug(f"DEBUG: Received {len(data)} bytes")
                    total += data
                except TimeoutError:
                    theend = True
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(XYTHON_SOCK)
            sock.send(f"TLSproxy {ipaddr}\n".encode("UTF8"))
            sock.send(total)
            try:
                ret = sock.recv(64000)
                print(f"DEBUG: getback {ret}")
                conn.send(ret)
            except ConnectionResetError:
                pass
            sock.close()
            conn.close()
            debug("DEBUG: proxyfied!")

sys.exit(0)
