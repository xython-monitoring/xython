#!/usr/bin/env python3

import argparse
import socket
import time
import os
import re
import sys
from importlib.metadata import version
from pysnmp import hlapi
from xython import xythonsrv

def snmp_get(oid, H):
    ret = {}
    ret["err"] = -1
    iterator = hlapi.getCmd(
    hlapi.SnmpEngine(),
    hlapi.CommunityData(H.snmp_community, mpModel=0),
    hlapi.UdpTransportTarget((H.gethost(), 161)),
    hlapi.ContextData(),
    hlapi.ObjectType(hlapi.ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        #print(f"errorIndication={errorIndication}")
        ret["errmsg"] = str(errorIndication)
        return ret
    if errorStatus:
        #print('%s at %s' % (errorStatus.prettyPrint(),
        #                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        ret["errmsg"] = str(errorStatus.prettyPrint())
        return ret
    #print(varBinds)
    for varBind in varBinds:
        #print("=======================")
        #print(type(varBind))
        #print(varBind[0])
        #print(varBind[1])
        #print("=======================")
        ret["pretty"] = ' = '.join([x.prettyPrint() for x in varBind])
        ret["oid"] = varBind[0]
        ret["v"] = varBind[1]
    ret["err"] = 0
    return ret

#List NIC names: .1.3.6.1.2.1.2.2.1.2
#Get Bytes IN: .1.3.6.1.2.1.2.2.1.10
#Get Bytes IN for NIC 4: .1.3.6.1.2.1.2.2.1.10.4
#Get Bytes OUT: .1.3.6.1.2.1.2.2.1.16
#Get Bytes OUT for NIC 4: .1.3.6.1.2.1.2.2.1.16.4
#
#CPU Statistics
#
#Load
#1 minute Load: .1.3.6.1.4.1.2021.10.1.3.1
#5 minute Load: .1.3.6.1.4.1.2021.10.1.3.2
#15 minute Load: .1.3.6.1.4.1.2021.10.1.3.3
#
#CPU times
#percentage of user CPU time: .1.3.6.1.4.1.2021.11.9.0
#raw user cpu time: .1.3.6.1.4.1.2021.11.50.0
#percentages of system CPU time: .1.3.6.1.4.1.2021.11.10.0
#raw system cpu time: .1.3.6.1.4.1.2021.11.52.0
#percentages of idle CPU time: .1.3.6.1.4.1.2021.11.11.0
#raw idle cpu time: .1.3.6.1.4.1.2021.11.53.0
#raw nice cpu time: .1.3.6.1.4.1.2021.11.51.0
#

def do_snmpd_disk(X, H, buf):
    #print("============================================")
    if H.snmp_disk_last is None:
        i = 0
        # TODO find a goo value or a better way
        while i < 100:
            ret = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.3.{i}', H)
            if ret['err'] == 0:
                partname = str(ret['v'])
                oid = str(ret['oid'])
                if partname[0] == '/':
                    X.debug(f"DEBUG: SNMP found disk {partname}")
                    H.snmp_disk_oid.append(i)
            else:
                if 'errmsg' in ret:
                    if 'timeout' in ret['errmsg']:
                        return buf
            i += 1
        H.snmp_disk_last = time.time()
    buf += f'[df]\n'
    for oid in H.snmp_disk_oid:
        X.debug(f"DEBUG: SNMP DISK check {oid}")
        disk_name = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.3.{oid}', H)
        disk_block_size = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.4.{oid}', H)
        disk_total = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.5.{oid}', H)
        disk_used = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.6.{oid}', H)
        dname = disk_name['v']
        dbs = int(disk_block_size['v'])
        dt = int(disk_total['v'])
        du = int(disk_used['v'])
        dt *= int(dbs / 1024)
        du *= int(dbs / 1024)
        df = dt - du
        percent = int(100 * du / dt)
        buf += f'{dname}\t{dt}\t{du}\t{df}\t{percent}%\t{dname}\n'
    return buf

def do_snmpd_memory(X, H, buf):
    ret = {}
    ret['snmp'] = ""
    swap_total = snmp_get('.1.3.6.1.4.1.2021.4.3.0', H)
    if swap_total["err"] != 0:
        ret['snmp'] = f'&red do_snmpd_memory: error with swap_total: {swap_total["errmsg"]}\n'
        return ret
    ret['snmp'] += swap_total["pretty"]
    swap_free = snmp_get('.1.3.6.1.4.1.2021.4.4.0', H)
    if swap_free["err"] != 0:
        ret['snmp'] = f'&red do_snmpd_memory: error with swap_free: {swap_free["errmsg"]}\n'
        return ret
    memory_total = snmp_get('.1.3.6.1.4.1.2021.4.5.0', H)
    if memory_total["err"] != 0:
        ret['snmp'] = f'&red do_snmpd_memory: error with memory_total: {memory_total["errmsg"]}\n'
        return ret
    memory_used = snmp_get('.1.3.6.1.4.1.2021.4.6.0', H)
    memory_free = snmp_get('.1.3.6.1.4.1.2021.4.11.0', H)
    memory_shared = snmp_get('.1.3.6.1.4.1.2021.4.13.0', H)
    memory_buffered = snmp_get('.1.3.6.1.4.1.2021.4.14.0', H)
    memt = memory_total['v']
    memf = memory_free['v']
    memu = memory_used['v']
    mems = memory_shared['v']
    memb = memory_buffered['v']
    ret['buf'] = f'[free]\nMem:\t{memt}\t{memu}\t{memf}\t{mems}\t{memb}\t{memf}\n'
    ret['snmp'] = 'DID memory OK\n'
    return ret

def do_snmpd_client(X, H):
    status = ""
    buf = f'proxy:snmpd\n[collector:]\nclient {H.name}.linux linux\n'
    sysdscr = snmp_get('.1.3.6.1.2.1.1.1.0', H)
    err = sysdscr['err']
    if err == 0:
        buf += f"[uname]\n{sysdscr['v']}\n"
        status += sysdscr['pretty']
        status += '\n'
    else:
        status += f"&red do_snmpd_client: error with sysdscr: {sysdscr['errmsg']}\n"
    if 'memory' in H.snmp_columns:
        ret = do_snmpd_memory(X, H, buf)
        #print("=========================")
        #print(ret)
        if 'buf' in ret:
            buf += ret['buf']
        if 'snmp' in ret:
            status += ret['snmp']
    if 'disk' in H.snmp_columns:
        buf = do_snmpd_disk(X, H, buf)
    buf += '[end]\n'
    #print("========================= unet_send")
    #print(buf)
    X.unet_send(buf)
    #print("========================= status")
    #print(status)
    #print("=========================")
    return status

def do_snmpd(X):
    for H in X.xy_hosts:
        X.debug(f"DEBUG: SNMP for {H.name}")
        buf = f"status+10m {H.name}.snmp green\n"
        if len(H.snmp_columns) == 0 and len(H.oidlist) == 0:
            continue
        if len(H.snmp_columns) > 0:
            ret = do_snmpd_client(X, H)
            #print("=========================")
            #print(ret)
            buf += ret
        for o in H.oidlist:
            X.debug(f"DEBUG: handle SNMP OID {o['oid']}")
            ret = snmp_get(o['oid'], H)
            if ret['err'] == 0:
                buf += f"did {o['oid']}\n"
                X.do_rrd(H.name, "snmp", o['name'], ret["v"])
            else:
                buf += f"did {o['oid']} {ret['errmsg']}\n"
        #print("========================= buf send")
        #print(buf)
        X.unet_send(buf)

def main():
    print(f'xython-snmpd v{version("xython")}')
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", "-d", help="increase debug level", action="store_true")
    parser.add_argument("--daemon", "-D", help="start daemon", action="store_true")
    parser.add_argument("--logdir", help="Override xython log directory", default="/var/log/xython/")
    parser.add_argument("--etcdir", help="Override xymon etc directory", default="/etc/xymon/")
    parser.add_argument("--xythonsock", help="Override xython socker patch", default="/run/xython/xython.sock")
    parser.add_argument("--xymonvardir", help="Override xymon var directory")
    parser.add_argument("--vardir", help="Override xython var directory")
    parser.add_argument("--quit", help="Quit after x seconds", type=int, default=0)
    args = parser.parse_args()

    X = xythonsrv()
    X.unixsock = args.xythonsock
    X.etcdir = args.etcdir
    X.xt_data= f"/var/lib/xython/"
    X.xt_rrd = f"{X.xt_data}/rrd/"
    X.lldebug = args.debug
    X.read_hosts()
    X.hosts_check_snmp_tags()
    while True:
        do_snmpd(X)
        time.sleep(20)

    sys.exit(0)
