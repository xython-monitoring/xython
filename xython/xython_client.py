#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import socket
import sys


def send(host, port, data):
    #print(f"SEND TO {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(data.encode("UTF8"))
    s.close()


def usage():
    print("xython version vTODO")
    print("Usage: /usr/xymon/client/bin/xymon [--debug] [--merge] [--proxy=http://ip.of.the.proxy:port/] RECIPIENT DATA")
    print("\tRECIPIENT: IP-address, hostname or URL")
    print('\tDATA: Message to send, or "-" to read from stdin')


def main():
    X_HOST = None
    X_PORT = 12346

    e = 0
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-h':
            usage()
            sys.exit(0)
        if X_HOST is None:
            x = sys.argv[i]
            if ':' in x:
                print("split")
                xs = x.split(":")
                X_HOST = xs[0]
                X_PORT = xs[1]
            else:
                X_HOST = x
            i += 1
            continue
        else:
            # X_HOST is not None so we have data
            send(X_HOST, X_PORT, sys.argv[i])
            sys.exit(0)
        print(f"ERROR: unknown argument {sys.argv[i]}")
        sys.exit(1)
    usage()
    sys.exit(0)


main()
