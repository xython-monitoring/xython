#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""


import os
import rrdtool
import socket
import re
import sys

RRD_COLOR = ["0000FF", "FF0000", "00CC00", "FF00FF", "555555", "880000", "000088", "008800",
             "008888", "888888", "880088", "FFFF00", "888800", "00FFFF", "00FF00", "AA8800",
             "AAAAAA", "DD8833", "DDCC33", "8888FF", "5555AA", "B428D3", "FF5555", "DDDDDD",
             "AAFFAA", "AAFFFF", "FFAAFF", "FFAA55", "55AAFF", "AA55FF"]

def load_graphs_cfg(etcdir):
    pgraphs = f"{etcdir}/graphs.cfg"
    try:
        fgraphs = open(pgraphs, 'r')
    except:
        print(f"ERROR: cannot open {pgraphs}")
        return None
    lines = fgraphs.readlines()
    section = None
    graphscfg = {}
    for line in lines:
        line = line.rstrip()
        line = line.lstrip()
        if len(line) == 0:
            continue
        if line[0] == '#':
            continue
        if line[0] == '[':
            if ']' not in line:
                print(f"ERROR: invalid line in {pgraphs} {line}")
                continue
            section = line.split('[')[1]
            section = section.split(']')[0]
            #print(f"SECTION is {section}")
            graphscfg[section] = {}
            graphscfg[section]["info"] = []
            continue
        if section is None:
            continue
        tokens = line.split(" ")
        keyword = tokens.pop(0)
        if keyword == 'YAXIS':
            graphscfg[section]['YAXIS'] = ' '.join(tokens)
            continue
        if keyword == 'TITLE':
            graphscfg[section]['TITLE'] = ' '.join(tokens)
            continue
        if keyword == 'FNPATTERN':
            graphscfg[section]['FNPATTERN'] = tokens[0]
            continue
        #print("loadgraph", f"DEBUG: load_graphs: {section} {line}\n<br>")
        graphscfg[section]["info"].append(line)
    return graphscfg

def get_ds_name(l):
    r = []
    for k in l.keys():
        if len(k) > 4:
            if k[-4:] == 'type':
                ds = k.split('[')[1].split(']')[0]
                r.append(ds)
    return r

def rrd_label(path, column):
    if path == f'{column},root':
        return '/'
    return path.replace(f"{column}.", '').replace(column, '').replace(',', '/').replace('.rrd', '')

def rrd_color(i):
    if i < 0:
        i = 0
    if i < len(RRD_COLOR):
        return RRD_COLOR[i]
    return '000000'

#print("Content-type: text/html\n")
#print('Content-type: image/png\r\n\r\n')
#print("Status: 200 OK\n")
#print("\n")

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
if "HOST" in POST:
    hostname = POST["HOST"]
if "hostname" in POST:
    hostname = POST["hostname"]
if "host" in POST:
    hostname = POST["host"]
if hostname is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    print("no hostname\n")
    sys.exit(0)

svc = None
if "SERVICE" in POST:
    svc = POST["SERVICE"]
if "service" in POST:
    svc = POST["service"]
svc = svc.rstrip()
if svc is None:
    print('Status: 400 Bad Request\n')
    print("\n")
    print("no service\n")
    sys.exit(0)

debug = False
if "debug" in POST:
    debug = True

action = 'view'
if "action" in POST:
    action = POST["action"].rstrip()

if action == 'menu':
    print("Content-type: text/html\n")
    print('<html>')
    sys.exit(0)
    
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('/run/xython/xython.sock')
except:
    print("FAIL to connect to xythond")
    sys.exit(0)
buf = f"GETRRD {hostname} {svc} {action}"
sock.send(buf.encode("UTF8"))
buf = sock.recv(640000)
sys.stdout.buffer.write(buf)
sock.close()

sys.exit(0)
