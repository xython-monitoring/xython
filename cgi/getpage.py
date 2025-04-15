#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import asyncio
import os
import sys


print("Content-type: text/html\n")

# arguments = cgi.FieldStorage()
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

page = None
hostname = None
if "PAGE" in POST:
    page = POST["PAGE"]
if "page" in POST:
    page = POST["page"]
if page is None:
    print('ERROR: no page argument')
    sys.exit(0)

XYTHON_SOCK = '/run/xython/xython.sock'

if "XYTHON_SOCK" in os.environ:
    XYTHON_SOCK = os.environ["XYTHON_SOCK"]

buf = f"GETPAGE {page}"


async def unix_xython(buf):
    reader, writer = await asyncio.open_unix_connection(path=XYTHON_SOCK)
    try:
        writer.write(buf.encode())
        await writer.drain()
        # print(f"SEND {buf}")
        while True:
            r = await reader.read(640000)
            if len(r) == 0:
                break
            # print(f"LEN={len(r)}")
            print(r.decode("UTF8"))
    except ConnectionResetError as e:
        print(f"getpage: FAIL to connect to xythond {str(e)}")
    except ConnectionRefusedError as e:
        print(f"getpage: FAIL to connect to xythond {str(e)}")
    except BrokenPipeError as e:
        print(f"getpage: FAIL to connect to xythond {str(e)}")
    try:
        writer.close()
        await writer.wait_closed()
    except BrokenPipeError:
        pass

asyncio.run(unix_xython(buf))
