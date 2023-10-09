#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import os
import socket
import sys


print("Content-type: text/html\n")
print("\n")

#arguments = cgi.FieldStorage()
POST = {}
stdin = sys.stdin.read()
args = stdin.split('&')
for arg in args:
    t = arg.split('=')
    if len(t)>1:
        k, v = arg.split('=')
        POST[k] = v
if "QUERY_STRING" in os.environ:
    QUERY_STRING = os.environ["QUERY_STRING"]
    args = QUERY_STRING.split('&')
    for arg in args:
        t = arg.split('=')
        if len(t)>1:
            k, v = arg.split('=')
            POST[k] = v


hostname = None
if "HOST" in POST:
    hostname = POST["HOST"]
if "hostname" in POST:
    hostname = POST["hostname"]
if hostname is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)

svc = None
if "SERVICE" in POST:
    svc = POST["SERVICE"]
if "service" in POST:
    svc = POST["service"]
if svc is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)
dsvc = None
if "DSERVICE" in POST:
    dsvc = POST["DSERVICE"]
if "dservice" in POST:
    dsvc = POST["dservice"]

#timebuf = arguments.getvalue("TIMEBUF")
if "TIMEBUG" in POST:
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
if cause is not None and duration is not None and action == 'ack':
    buf = "acknowledge %s.%s %s %s\n" % (hostname, svc, duration, cause)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # TODO this must be not hardcoded
    sock.connect('/run/xython/xython.sock')
    sock.send(buf.encode("UTF8"))
    sock.close()
if cause is not None and duration is not None and action == 'disable':
    buf = "disable %s.%s %s %s\n" % (hostname, dsvc, duration, cause)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    # TODO this must be not hardcoded
    sock.connect('/run/xython/xython.sock')
    sock.send(buf.encode("UTF8"))
    sock.close()

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('/run/xython/xython.sock')
except:
    print("FAIL to connect to xythond")
    sys.exit(0)
if timebuf is None:
    buf = "GETSTATUS %s %s" % (hostname, svc)
else:
    buf = "GETSTATUS %s %s %s" % (hostname, svc, timebuf)
sock.send(buf.encode("UTF8"))
buf = sock.recv(640000)
print(buf.decode("UTF8"))
sock.close()

sys.exit(0)
