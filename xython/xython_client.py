#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

from importlib.metadata import version
import socket
import sys

lldebug = 0

def debug(msg):
    if lldebug > 0:
        print(msg)


def send(host, port, data):
    debug(f"SEND TO {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
    except socket.gaierror as e:
        print(f"ERROR: fail to connect on {host}:{port} {str(e)}")
        return
    except ConnectionRefusedError as e:
        print(f"ERROR: fail to connect on {host}:{port} {str(e)}")
        return
    s.sendall(data.encode("UTF8"))
    #r = s.recv(64000)
    #print(r)
    s.close()


def usage():
    print(f'xython v{version("xython")}')
    print("Usage: /usr/xymon/client/bin/xymon [--debug] [--merge] [--proxy=http://ip.of.the.proxy:port/] RECIPIENT DATA")
    print("\tRECIPIENT: IP-address, hostname or URL")
    print('\tDATA: Message to send, or "-" to read from stdin')


def main():
    global lldebug
    X_HOST = None
    X_PORT = 12346

    e = 0
    print(f"DEBUG: argv={len(sys.argv)}")
    args = sys.argv
    args.pop(0)
    while len(args) > 0:
        arg = args.pop(0)
        if arg == '-h':
            usage()
            sys.exit(0)
        if arg == '--debug':
            lldebug = 1
            continue
        debug(f"DEBUG: check {arg}")
        if X_HOST is None:
            if ':' in arg:
                debug("DEBUG: split {x}")
                xs = arg.split(":")
                X_HOST = xs[0]
                X_PORT = xs[1]
            else:
                X_HOST = arg
            continue
        # X_HOST is not None so we have data
        data = arg
        for arg in args:
            data += f" {arg}"
        data += "\n"
        send(X_HOST, int(X_PORT), data)
        sys.exit(0)
    usage()
    sys.exit(0)


main()
