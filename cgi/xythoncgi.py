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

# upper bound on the POST body we are willing to read into memory
MAX_BODY = 1 * 1024 * 1024


def fail(msg):
    print(msg)
    sys.exit(0)


def is_valid_hostname(hostname):
    # mirror of xython.common.is_valid_hostname: reject path separators,
    # whitespace and leading/trailing dots so hostname cannot traverse
    # the histlogs filesystem tree on the daemon side
    if not hostname:
        return False
    if hostname[0] == '.' or hostname[-1] == '.':
        return False
    return re.match(r"^[a-zA-Z0-9_.-]+\Z", hostname) is not None


def is_valid_column(column):
    if not column:
        return False
    return re.match(r"^[a-zA-Z0-9_-]+\Z", column) is not None


def is_single_token(value):
    # a protocol field that must not contain whitespace/newline, otherwise it
    # would shift the positional arguments of the daemon command
    if not value:
        return False
    return re.match(r"^\S+\Z", value) is not None


def parse_qs_flat(buf):
    # crash-proof, URL-decoding query parser; last value wins for repeats
    out = {}
    for k, v in urllib.parse.parse_qs(buf, keep_blank_values=True).items():
        out[k] = v[-1]
    return out


POST = {}
if "QUERY_STRING" in os.environ:
    POST = parse_qs_flat(os.environ["QUERY_STRING"])
else:
    print("ERROR: not runned as CGI")
    sys.exit(1)

method = os.environ.get("REQUEST_METHOD", "")
# form submissions (ack/disable) arrive as a POST body; body values take
# precedence over the query string
if method == "POST":
    clen = os.environ.get("CONTENT_LENGTH")
    if clen is not None and clen != "":
        try:
            blen = int(clen)
        except ValueError:
            fail("ERROR: invalid CONTENT_LENGTH")
        if blen < 0 or blen > MAX_BODY:
            fail("ERROR: body too large")
        POST.update(parse_qs_flat(sys.stdin.read(blen)))


def check_same_origin():
    # CSRF defense: state-changing actions must be POST, and when the browser
    # supplies an Origin/Referer it must match the served host. Scripted
    # clients (curl) that send neither header are still allowed.
    if method != "POST":
        fail("ERROR: action requires POST")
    host = os.environ.get("HTTP_HOST")
    src = os.environ.get("HTTP_ORIGIN") or os.environ.get("HTTP_REFERER")
    if src and host:
        netloc = urllib.parse.urlsplit(src).netloc
        if netloc and netloc != host:
            fail("ERROR: cross-origin request rejected")


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
if not is_valid_column(svc):
    fail('ERROR: invalid service')
dsvc = None
if "DSERVICE" in POST:
    dsvc = POST["DSERVICE"]
if "dservice" in POST:
    dsvc = POST["dservice"]
if dsvc is not None and not is_valid_column(dsvc):
    fail('ERROR: invalid dservice')

if "TIMEBUF" in POST:
    timebuf = POST["TIMEBUF"]
else:
    timebuf = None
if timebuf is not None and not is_single_token(timebuf):
    fail('ERROR: invalid timebuf')
if "duration" in POST:
    duration = POST["duration"]
else:
    duration = None
if duration is not None and not is_single_token(duration):
    fail('ERROR: invalid duration')
if "cause" in POST:
    cause = POST["cause"]
else:
    cause = None
if cause is not None and ("\n" in cause or "\r" in cause):
    fail('ERROR: invalid cause')
if "action" in POST:
    action = POST["action"]
else:
    action = None

XYTHON_SOCK = '/run/xython/xython.sock'

if "XYTHON_SOCK" in os.environ:
    XYTHON_SOCK = os.environ["XYTHON_SOCK"]

def send_action(buf):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(XYTHON_SOCK)
        sock.send(buf.encode("UTF8"))
    except (FileNotFoundError, ConnectionError) as e:
        fail(f"FAIL to connect to xythond, {str(e)}")
    finally:
        sock.close()


if action == 'ack':
    check_same_origin()
    if cause is None:
        print("ERROR: ack need cause")
        sys.exit(0)
    if duration is None:
        print("ERROR: ack need duration")
        sys.exit(0)
    send_action("acknowledge %s.%s %s %s\n" % (hostname, svc, duration, cause))
elif action == 'disable':
    check_same_origin()
    if cause is None:
        print("ERROR: disable need cause")
        sys.exit(0)
    if duration is None:
        print("ERROR: disable need duration")
        sys.exit(0)
    if dsvc is None:
        print("ERROR: disable need dsvc")
        sys.exit(0)
    send_action("disable %s.%s %s %s\n" % (hostname, dsvc, duration, cause))
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
