#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import argparse
import time
from xython import xythonsrv
import sys

def main():
    print("xython vTODO")
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", "-d", help="increase debug level", action="store_true")
    parser.add_argument("--daemon", "-D", help="start daemon", action="store_true")
    parser.add_argument("--xython", "-x", help="Load files from xython", type=int, default=2)
    parser.add_argument("--tload", "-T", help="test reading configuration and data", action="store_true")
    parser.add_argument("--dump", help="test reading configuration and data", action="store_true")
    parser.add_argument("--readonly", "-R", help="Readonly mode, do not write anything in XYMONVAR (except web pages)", action="store_true")
    parser.add_argument("--netport", help="Network port", default=1984)
    parser.add_argument("--logdir", help="Override xython log directory", default="/var/log/xython/")
    parser.add_argument("--etcdir", help="Override xymon etc directory", default="/etc/xymon/")
    parser.add_argument("--wwwdir", help="Override xython www directory")
    parser.add_argument("--xymonvardir", help="Override xymon var directory")
    parser.add_argument("--vardir", help="Override xython var directory")
    args = parser.parse_args()

    X = xythonsrv()
    X.set_netport(int(args.netport))
    X.edebug = args.debug
    X.readonly = args.readonly
    X.xythonmode = args.xython
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
    X.init()
    if args.dump:
        X.print()
        sys.exit(0)

    if args.daemon:
        X.net_start()
        X.unet_start()
        while True:
            X.unet_loop()
            X.net_loop()
            X.scheduler()
            time.sleep(0.01)
        sys.exit(0)

    if args.tload:
        for rule in X.rules["PORT"]:
            rule.dump()
        for Hh in X.xy_hosts:
            print("DUMP RULE FOR %s" % Hh.name)
            #for rule in Hh.rules["PORT"]:
            #    rule.dump()
            #for rule in Hh.rules["PROC"]:
            #    rule.dump()
        X.gen_html("all", None, None, None)
