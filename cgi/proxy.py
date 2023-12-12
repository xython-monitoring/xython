#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import os
import re
import socket
import sys


XYTHON_SOCK = '/run/xython/xython.sock'
ipaddr = None

if "XYTHON_SOCK" in os.environ:
    XYTHON_SOCK = os.environ["XYTHON_SOCK"]

print("Content-type: text/plain\n")

if 'REQUEST_METHOD' not in os.environ:
    print("ERROR: no REQUEST_METHOD")
    sys.exit(0)
if os.environ['REQUEST_METHOD'] != 'POST':
    print("ERROR: REQUEST_METHOD is not POST")
    sys.exit(0)

if 'CONTENT_TYPE' not in os.environ:
    print("ERROR: no CONTENT_TYPE")
    sys.exit(0)
contype = os.environ['CONTENT_TYPE']
if 'multipart/form-data' not in contype:
    print("ERROR: CONTENT_TYPE is not multipart/form-data")
    sys.exit(0)
if 'boundary' not in contype:
    print("ERROR: no boundary in CONTENT_TYPE")
    sys.exit(0)
ret = re.search(r"(boundary=)([a-zA-Z0-9-]*)", contype)
boundary = ret.group(2).rstrip()
#print(contype)
#print(ret.groups())
#print(f"BOUNDARY={boundary}")
data = sys.stdin.read()
lines = data.split('\n')
i = 0
header = True
#print("===== start ====")
line = lines.pop(0)
line = line.rstrip()
if line != "--" + boundary:
    print("ERROR: no boundary in content")
    sys.exit(0)

# now remove header
while header:
    line = lines.pop(0)
    line = line.rstrip()
    if line == "":
        header = False
    if len(lines) == 0:
        # we are still in header, but nothing to eat
        print("ERROR: wrong format")
        sys.exit(0)

# now seek the boundary
end = None
for line in lines:
    line = line.rstrip()
    if line == "--" + boundary + "--":
        #print(f"END found at {i}")
        end = i
    i += 1
if end is None:
    print("ERROR: no end")
    sys.exit(0)

total = len(lines)
i = total - 1
while i >= end:
    line = lines.pop(i)
    #print(f"DEBUG: remove {line}")
    i -= 1

data = "\n".join(lines)

if "REMOTE_ADDR" in os.environ:
    ipaddr = os.environ["REMOTE_ADDR"]
# TODO PROXY FOR ADDR
if data is None or ipaddr is None:
    print("ERROR: no REMOTE_ADDR")
    sys.exit(0)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect(XYTHON_SOCK)
except FileNotFoundError:
    print(f"FAIL to connect to xythond, no such file or directory")
    sys.exit(0)
except ConnectionRefusedError:
    print(f"FAIL to connect to xythond")
    sys.exit(0)
try:
    sock.send(f"HTTPTLSproxy {ipaddr}\n".encode("UTF8"))
    sock.send(data.encode("UTF8"))
    buf = sock.recv(640000)
    print(buf.decode("UTF8"))
except ConnectionResetError:
    # either we fail to write or read
    # cannot do anything
    print("ERROR: fail to communicate with xython")
    pass
sock.close()

sys.exit(0)
