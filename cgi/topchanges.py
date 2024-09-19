#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

from datetime import datetime
import os
import re
import socket
import sys

XYTHON_SOCK = '/run/xython/xython.sock'

if "XYTHON_SOCK" in os.environ:
    XYTHON_SOCK = os.environ["XYTHON_SOCK"]
ts_start = 0
ts_end = 20000000

print("Content-type: text/html\n")

if 'REQUEST_METHOD' not in os.environ:
    print("ERROR: no REQUEST_METHOD")
    sys.exit(0)
if os.environ['REQUEST_METHOD'] != 'GET':
    print("ERROR: REQUEST_METHOD is not GET")
    sys.exit(0)

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

# starttime
if "FROMTIME" not in POST:
    print("ERROR: no starttime")
    sys.exit(0)
FROMTIME = POST["FROMTIME"]
if FROMTIME == "":
    starttime = 0
else:
    FROMTIME = FROMTIME.replace('%2F', '/')
    FROMTIME = FROMTIME.replace('%40', '@')
    FROMTIME = FROMTIME.replace('%3A', ':')
    try:
        date = datetime.strptime(FROMTIME, "%Y/%m/%d@%H:%M:%S")
    except ValueError:
        print("ERROR: invalid FROMTIME date")
        sys.exit(0)
    starttime = int(date.timestamp())

# endtime
if "TOTIME" not in POST:
    print("ERROR: no TOTIME")
    sys.exit(0)
TOTIME = POST["TOTIME"]
if TOTIME == "":
    endtime = 4000000000
else:
    TOTIME = TOTIME.replace('%2F', '/')
    TOTIME = TOTIME.replace('%40', '@')
    TOTIME = TOTIME.replace('%3A', ':')
    try:
        date = datetime.strptime(TOTIME, "%Y/%m/%d@%H:%M:%S")
    except ValueError:
        print("ERROR: invalid TOTIME date")
        sys.exit(0)
    endtime = int(date.timestamp())

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect(XYTHON_SOCK)
except FileNotFoundError:
    print(f"FAIL to connect to xythond, no such file or directory")
    sys.exit(0)
except ConnectionRefusedError:
    print(f"FAIL to connect to xythond")
    sys.exit(0)
sock.send(f"TOPCHANGES {FROMTIME} {TOTIME}\n".encode("UTF8"))
#sock.send(data.encode("UTF8"))
buf = sock.recv(640000)
print(buf.decode("UTF8"))
sock.close()

sys.exit(0)
