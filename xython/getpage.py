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
if "PAGE" in POST:
    page = POST["PAGE"]
if "page" in POST:
    page = POST["page"]
if page is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('/run/xython/xython.sock')
except:
    print("FAIL to connect to xythond")
    sys.exit(0)
buf = f"GETPAGE {page}"
sock.send(buf.encode("UTF8"))
buf = sock.recv(640000)
print(buf.decode("UTF8"))
sock.close()

sys.exit(0)
