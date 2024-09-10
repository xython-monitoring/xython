#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import os
import socket
import sys

POST = {}
stdin = sys.stdin.read()
args = stdin.split('&')
for arg in args:
    t = arg.split('=')
    if len(t) > 1:
        k, v = arg.split('=')
        POST[k] = v
if "QUERY_STRING" in os.environ:
    QUERY_STRING = os.environ["QUERY_STRING"]
    args = QUERY_STRING.split('&')
    for arg in args:
        t = arg.split('=')
        if len(t) > 1:
            k, v = arg.split('=')
            POST[k] = v

hostname = None
if "HOST" in POST:
    hostname = POST["HOST"]
if "hostname" in POST:
    hostname = POST["hostname"]
if "host" in POST:
    hostname = POST["host"]
if hostname is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    print("no hostname\n")
    sys.exit(0)

svc = None
if "SERVICE" in POST:
    svc = POST["SERVICE"]
if "service" in POST:
    svc = POST["service"]
if svc is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    print("no service\n")
    sys.exit(0)
svc = svc.rstrip()

debug = False
if "debug" in POST:
    debug = True

SOCKPATH = '/run/xython/xython.sock'
# if "sockpath" in POST:
#    sockpath = POST['sockpath']
#    print(f"DEBUG: check {sockpath}")
#    if re.match("./tests/.*", sockpath):
#        SOCKPATH = sockpath
#    else:
#        print('Status: 400 Bad Request\n')
#        print("\n")
#        print("invalid sockpath\n")
#        sys.exit(0)
#
action = 'view'
if "action" in POST:
    action = POST["action"].rstrip()

if action == 'menu':
    print("Content-type: text/html\n")
    print('<html>')
    sys.exit(0)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect(SOCKPATH)
except:
    print('Status: 500 Internal Server Error\n\n')
    print("showgraph: FAIL to connect to xythond")
    sys.exit(0)
buf = f"GETRRD {hostname} {svc} {action}"
sock.send(buf.encode("UTF8"))
buf = sock.recv(640000)
sys.stdout.buffer.write(buf)
sock.close()

sys.exit(0)
