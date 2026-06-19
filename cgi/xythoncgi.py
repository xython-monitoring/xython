#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import os
import re
import socket
import sys
import urllib.parse


print("Content-type: text/html\n")


def is_valid_hostname(hostname):
    # mirror of xython.common.is_valid_hostname: reject path separators,
    # whitespace and leading/trailing dots so hostname cannot traverse
    # the histlogs filesystem tree on the daemon side
    if not hostname:
        return False
    if hostname[0] == '.' or hostname[-1] == '.':
        return False
    return re.match(r"^[a-zA-Z0-9_.-]+\Z", hostname) is not None

POST = {}
if "QUERY_STRING" in os.environ:
    parsed = urllib.parse.parse_qs(os.environ["QUERY_STRING"], keep_blank_values=True)
    POST = {k: v[-1] for k, v in parsed.items()}
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
if not is_valid_hostname(hostname):
    print('ERROR: invalid hostname')
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
    sock.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    print(b"".join(chunks).decode("UTF8"))
    #buf = sock.recv(640000)
    #print(buf.decode("UTF8"))
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
