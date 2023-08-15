#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import argparse
import socket
import ssl
import sys

def debug(msg):
    if args.debug:
        print(msg)

def main():
    print("test")

print("xython-tlsd 0.1")

parser = argparse.ArgumentParser()
parser.add_argument("--debug", "-d", help="increase debug level", action="store_true")
parser.add_argument("--netport", help="Network port", default=1985)
parser.add_argument("--logdir", help="Override xython log directory", default="/var/log/xython/")
parser.add_argument("--etcdir", help="Override xymon etc directory", default="/etc/xymon/")
parser.add_argument("--tlskey", help="Override xython TLS key")
parser.add_argument("--tlscrt", help="Override xython TLS certificate")
parser.add_argument("--quit", help="Quit after x seconds", type=int, default=0)
args = parser.parse_args()

XYTHON_SOCK='/tmp/xython.sock'
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
    if keyword == 'XYTHON_TLS_CRT':
        TLS_CRT = tokens[1]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(TLS_CRT, TLS_KEY)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('0.0.0.0', args.netport))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            ipaddr = addr[0]
            debug(f"Got connection from {ipaddr}")
            data = conn.recv(64384)
            conn.close()
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(XYTHON_SOCK)
            sock.send(f"TLSproxy {ipaddr}\n".encode("UTF8"))
            sock.send(data)
            sock.close()

sys.exit(0)
