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
import urllib.parse

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
if "QUERY_STRING" in os.environ:
    parsed = urllib.parse.parse_qs(os.environ["QUERY_STRING"], keep_blank_values=True)
    POST = {k: v[-1] for k, v in parsed.items()}
else:
    print("ERROR: not runned as CGI")
    sys.exit(1)

# starttime
if "FROMTIME" not in POST:
    print("ERROR: no starttime")
    sys.exit(0)
FROMTIME = POST["FROMTIME"]
if FROMTIME == "":
    starttime = 0
else:
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
    try:
        date = datetime.strptime(TOTIME, "%Y/%m/%d@%H:%M:%S")
    except ValueError:
        print("ERROR: invalid TOTIME date")
        sys.exit(0)
    endtime = int(date.timestamp())

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect(XYTHON_SOCK)
    sock.send(f"TOPCHANGES {FROMTIME} {TOTIME}\n".encode("UTF8"))
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
