#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import cgi
import socket
import sys


print("Content-type: text/html\n")
print("\n")

arguments = cgi.FieldStorage()

hostname = arguments.getvalue("HOST")
if hostname is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)

svc = arguments.getvalue("SERVICE")
if svc is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    sys.exit(0)

timebuf = arguments.getvalue("TIMEBUF")

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/tmp/xython.sock")
if timebuf is None:
    buf = "GETSTATUS %s %s" % (hostname, svc)
else:
    buf = "GETHIST %s %s %s" % (hostname, svc, timebuf)
sock.send(buf.encode("UTF8"))
buf = sock.recv(640000)
print(buf.decode("UTF8"))
sock.close()

sys.exit(0)
