#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import os
import socket
import sys


print("Content-type: text/html\n")

POST = {}
if "QUERY_STRING" in os.environ:
    QUERY_STRING = os.environ["QUERY_STRING"]
    args = QUERY_STRING.split('&')
    for arg in args:
        t = arg.split('=')
        if len(t) > 1:
            k, v = arg.split('=')
            POST[k] = v
else:
    print("ERROR: not runned as CGI")
    sys.exit(1)


hostname = None
if "HOST" in POST:
    hostname = POST["HOST"]
if "hostname" in POST:
    hostname = POST["hostname"]
if hostname is None:
    print('ERROR: no hostname')
    sys.exit(0)

svc = None
if "SERVICE" in POST:
    svc = POST["SERVICE"]
if "service" in POST:
    svc = POST["service"]
if svc is None:
    print('ERROR: no service')
    sys.exit(0)
dsvc = None
if "DSERVICE" in POST:
    dsvc = POST["DSERVICE"]
if "dservice" in POST:
    dsvc = POST["dservice"]

if "TIMEBUF" in POST:
    timebuf = POST["TIMEBUF"]
else:
    timebuf = None
if "duration" in POST:
    duration = POST["duration"]
else:
    duration = None
if "cause" in POST:
    cause = POST["cause"]
else:
    cause = None
if "action" in POST:
    action = POST["action"]
else:
    action = None

XYTHON_SOCK = '/run/xython/xython.sock'

if "XYTHON_SOCK" in os.environ:
    XYTHON_SOCK = os.environ["XYTHON_SOCK"]

if action == 'ack':
    if cause is None:
        print("ERROR: ack need cause")
        sys.exit(0)
    if duration is None:
        print("ERROR: ack need duration")
        sys.exit(0)
    buf = "acknowledge %s.%s %s %s\n" % (hostname, svc, duration, cause)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(XYTHON_SOCK)
    sock.send(buf.encode("UTF8"))
    sock.close()
elif action == 'disable':
    if cause is None:
        print("ERROR: disable need cause")
        sys.exit(0)
    if duration is None:
        print("ERROR: disable need duration")
        sys.exit(0)
    if dsvc is None:
        print("ERROR: disable need dsvc")
        sys.exit(0)
    buf = "disable %s.%s %s %s\n" % (hostname, dsvc, duration, cause)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(XYTHON_SOCK)
    sock.send(buf.encode("UTF8"))
    sock.close()
elif action is not None:
    print("ERROR: invalid action")
    sys.exit(0)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect(XYTHON_SOCK)
    if timebuf is None:
        buf = "GETSTATUS %s %s\n" % (hostname, svc)
    else:
        buf = "GETSTATUS %s %s %s\n" % (hostname, svc, timebuf)
    sock.send(buf.encode("UTF8"))
    buf = sock.recv(640000)
    print(buf.decode("UTF8"))
    sock.close()
except FileNotFoundError as e:
    print(f"FAIL to connect to xythond, {str(e)}")
    sys.exit(0)
except ConnectionRefusedError as e:
    print(f"FAIL to connect to xythond, {str(e)}")
    sys.exit(0)
except ConnectionResetError as e:
    print(f"FAIL to connect to xythond, {str(e)}")
    sys.exit(0)

sys.exit(0)
