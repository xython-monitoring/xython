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


#hostname = arguments.getvalue("HOST")
if "HOST" in POST:
    hostname = POST["HOST"]
else:
    hostname = POST["hostname"]
if hostname is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)

if "SERVICE" in POST:
    svc = POST["SERVICE"]
else:
    svc = POST["service"]
if svc is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)

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
if cause is not None and duration is not None:
    buf = "acknowledge %s.%s %s %s\n" % (hostname, svc, duration, cause)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect("/tmp/xython.sock")
    sock.send(buf.encode("UTF8"))
    sock.close()

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/tmp/xython.sock")
if timebuf is None:
    buf = "GETSTATUS %s %s" % (hostname, svc)
else:
    buf = "GETSTATUS %s %s %s" % (hostname, svc, timebuf)
sock.send(buf.encode("UTF8"))
buf = sock.recv(640000)
print(buf.decode("UTF8"))
sock.close()

sys.exit(0)
