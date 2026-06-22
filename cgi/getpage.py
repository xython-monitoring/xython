#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import asyncio
import os
import re
import sys
import urllib.parse


print("Content-type: text/html\n")


def is_valid_page(page):
    # page/subpage names are config tokens (e.g. "servers/linux"); allow the
    # slash for subpages but reject whitespace/newlines that would break the
    # GETPAGE command frame sent to the daemon
    if not page:
        return False
    return re.match(r"^[a-zA-Z0-9_./:@-]+\Z", page) is not None

POST = {}
if "QUERY_STRING" in os.environ:
    parsed = urllib.parse.parse_qs(os.environ["QUERY_STRING"], keep_blank_values=True)
    POST = {k: v[-1] for k, v in parsed.items()}
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
if not is_valid_page(page):
    print('ERROR: invalid page argument')
    sys.exit(0)

XYTHON_SOCK = '/run/xython/xython.sock'

if "XYTHON_SOCK" in os.environ:
    XYTHON_SOCK = os.environ["XYTHON_SOCK"]

buf = f"GETPAGE {page}"


async def unix_xython(buf):
    try:
        reader, writer = await asyncio.open_unix_connection(path=XYTHON_SOCK)
    except (FileNotFoundError, ConnectionRefusedError, ConnectionResetError) as e:
        print(f"getpage: FAIL to connect to xythond {str(e)}")
        return
    try:
        writer.write(buf.encode())
        await writer.drain()
        # half-close so xythond sees EOF immediately instead of waiting for
        # its read timeout before answering
        writer.write_eof()
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
