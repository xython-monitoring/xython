#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import argparse
import asyncio
from xython import xythonsrv
import sys
from importlib.metadata import version


def main():
    print(f'xythond v{version("xython")}')
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", "-d", help="increase debug level", action="store_true")
    parser.add_argument("--daemon", "-D", help="start daemon", action="store_true")
    parser.add_argument("--ipv6", "-6", help="Enable IPV6", action="store_true")
    parser.add_argument("--xython", "-x", help="Load files from xython", type=int, default=2)
    parser.add_argument("--tload", "-T", help="test reading configuration and data", action="store_true")
    parser.add_argument("--dump", help="test reading configuration and data", action="store_true")
    parser.add_argument("--readonly", "-R", help="Readonly mode, do not write anything in XYMONVAR (except web pages)", action="store_true")
    parser.add_argument("--netport", help="Network port", default=1984)
    parser.add_argument("--tlsport", help="Network port", default=1985)
    parser.add_argument("--logdir", help="Override xython log directory", default="/var/log/xython/")
    parser.add_argument("--etcdir", help="Override xymon etc directory", default="/etc/xymon/")
    parser.add_argument("--xythonsock", help="Override xython socker patch", default="/run/xython/xython.sock")
    parser.add_argument("--wwwdir", help="Override xython www directory")
    parser.add_argument("--xymonvardir", help="Override xymon var directory")
    parser.add_argument("--vardir", help="Override xython var directory")
    parser.add_argument("--debugs", help="Extra debug section separated by comma")
    parser.add_argument("--quit", help="Quit after x seconds", type=int, default=0)
    parser.add_argument("--tlskey", help="Override xython TLS key")
    parser.add_argument("--tlscrt", help="Override xython TLS certificate")
    args = parser.parse_args()

    X = xythonsrv()
    X.unixsock = args.xythonsock
    X.set_netport(int(args.netport))
    X.set_tlsport(int(args.tlsport))
    if args.tlskey:
        X.tls_key = args.tlskey
    if args.tlscrt:
        X.tls_cert = args.tlscrt
    X.lldebug = args.debug
    X.readonly = args.readonly
    X.xythonmode = args.xython
    if args.ipv6:
        X.ipv6 = True
    if X.xythonmode == 0 and not X.readonly:
        X.error("ERROR: xython mode 0 is dangerous")
        sys.exit(1)
    X.xt_logdir = args.logdir
    X.etcdir = args.etcdir
    if args.xymonvardir:
        X.set_xymonvar(args.xymonvardir)
    if args.vardir:
        X.xt_data = args.vardir
        X.log("main", f"xython var directory is now {X.xt_data}")
    if args.wwwdir:
        X.wwwdir = args.wwwdir
        X.log("main", f"WWW directory is now {X.wwwdir}")
    if args.debugs:
        X.debugs = args.debugs.split(",")
    X.init()
    if args.dump:
        X.print()
        sys.exit(0)
    if args.quit > 0:
        X.quit = args.quit

    if args.daemon:
        asyncio.run(X.run())
        sys.exit(0)

    if args.tload:
        for rule in X.rules["PORT"]:
            rule.dump()
        for Hh in X.xy_hosts:
            print("DUMP RULE FOR %s" % X.xy_hosts[Hh].name)
            # for rule in Hh.rules["PORT"]:
            #    rule.dump()
            # for rule in Hh.rules["PROC"]:
            #    rule.dump()
        X.gen_html("all", None, None, None)
