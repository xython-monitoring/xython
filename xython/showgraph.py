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

action = None
if "action" in POST:
    action = POST["action"].rstrip()

if action == 'menu':
    print("Content-type: text/html\n")
    print('<html>')
    sys.exit(0)
    

# TODO get this
RRDDIR = '/var/lib/xython/rrd'

graphscfg = load_graphs_cfg("/home/cpp/xython/etc/xython/")
if graphscfg is None:
    print('Status: 400 Bad Request\n\n')
    print("ERROR: fail to open graphs.cfg")
    sys.exit(1)
graph = svc
if svc not in graphscfg:
    print('Status: 400 Bad Request\n\n')
    print(f"ERROR: SERVICE {graph} not found in graph<br>")
    sys.exit(0)
#print(graphscfg[svc])
rrdlist = []
basedir = f"{RRDDIR}/{hostname}"
if 'FNPATTERN' in graphscfg[graph]:
    rrdpattern = graphscfg[graph]["FNPATTERN"]
    for rrd in os.listdir(basedir):
        #print(f"CHECK {rrd} vs {rrdpattern}<br>")
        if re.match(rrdpattern, rrd):
            rrdlist.append(rrd)
else:
    rrdpath = f'{basedir}/{graph}.rrd'
    #print(rrdpath)
    if os.path.exists(rrdpath):
        rrdlist.append(f"{graph}.rrd")
        #print("exists")
if graph == 'sensor':
    allrrds = os.listdir(basedir)
    if 'sensor' in allrrds:
        adapters = os.listdir(f"{basedir}/sensor/")
        for adapter in adapters:
            rrd_sensors = os.listdir(f"{basedir}/sensor/{adapter}/")
            for rrd_sensor in rrd_sensors:
                allrrds.append(f"sensor/{adapter}/{rrd_sensor}")
    for rrd in allrrds:
        if 'sensor/' in rrd:
            rrdlist.append(rrd)
if len(rrdlist) == 0:
    print('Status: 400 Bad Request\n\n')
    print("ERROR: RRD list is empty")
    sys.exit(0)

#print("OK<br>")
#print(rrdlist)
#print('<br>')
base = ['-',
'--width=576', '--height=140',
'--vertical-label="% Full"',
'--start=end-96h'
]
if 'YAXIS' in graphscfg[graph]:
    base.append(f'--vertical-label={graphscfg[graph]["YAXIS"]}')
else:
    base.append(f'--vertical-label="unset"')
if 'TITLE' in graphscfg[graph]:
    base.append(f'--title={graphscfg[graph]["TITLE"]} on {hostname}')
else:
    base.append(f'--title={graph} on {hostname}')
i = 0
sensor_adapter = None
for rrd in rrdlist:
    fname = str(rrd.replace(".rrd", ""))
    rrdfpath = f"{basedir}/{rrd}"
    #print(f"fnam={fname}<br>")
    #print('<br>')
    label = rrd_label(fname, 'conn')
    info = rrdtool.info(rrdfpath)
    template = graphscfg[graph]["info"]
    if graph == 'sensor':
        adapter = os.path.dirname(rrd).split('/')[-1]
    #print(f"DEBUG: sensor_rrd: adapter is {adapter}")
    # remove adapter name
        label = re.sub('/.*/', '', label)
    if graph == 'sensor' and sensor_adapter != adapter:
    #print(f"DEBUG: sensor_rrd: add comment {adapter}")
        sensor_adapter = adapter
        base.append(f'COMMENT:{adapter}\\n')
    label = label.ljust(20)
    #print(f"DEBUG: label is {label}<br>")
    for line in template:
        for dsname in get_ds_name(info):
            #print(f"DEBUG: dsname={dsname}<br>")
            line = line.replace('@RRDDS@', dsname)
            line = line.replace('@COLOR@', rrd_color(i))
            line = line.replace('@RRDIDX@', f"{i}")
            line = line.replace('@RRDFN@', rrdfpath)
        if graph == 'la':
            line = line.replace('la.rrd', rrdfpath)
        line = line.replace('@RRDFN@', rrdfpath)
        line = line.replace('@RRDPARAM@', f"{label}")
        base.append(line)
    i += 1
    #rrdup = xytime(time.time()).replace(':', '\\:')
    #base.append(f'COMMENT:Updated\\: {rrdup}')
#print("==================<br>")
#print(base)
#print('<br>')
try:
    ret = rrdtool.graphv(base)
# TODO check this ret
except rrdtool.OperationalError as e:
    print(e)
    sys.exit(1)
sys.stdout.buffer.write(b"Content-type: image/png\r\n\r\n")
if debug:
    print(ret['image'])
else:
    sys.stdout.buffer.write(ret['image'])
sys.exit(0)

