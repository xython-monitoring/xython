#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

from celery import Celery
import subprocess
import os
import paramiko
from paramiko import SSHClient
import logging
from pysnmp import hlapi
import pysnmp
import pyasn1
import time
import re
import requests
import socket
import ssl
import urllib3
from importlib.metadata import version
from xython.common import setcolor
from xython.common import xytime

from datetime import datetime

# requests use urllib3, we dont want to see TLS warnings about self signed cert
urllib3.disable_warnings()

# TODO permit to configure localhost
app = Celery('tasks', backend='redis://localhost', broker='redis://localhost')


def snmp_get(oid, hostname, port, snmp_community):
    ret = {}
    ret["err"] = -1
    try:
        iterator = hlapi.getCmd(
            hlapi.SnmpEngine(),
            hlapi.CommunityData(snmp_community, mpModel=0),
            hlapi.UdpTransportTarget((hostname, port)),
            hlapi.ContextData(),
            hlapi.ObjectType(hlapi.ObjectIdentity(oid))
        )
    except pysnmp.error.PySnmpError as e:
        print(str(e))
        ret["errmsg"] = str(e)
        return ret
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    except pyasn1.error.PyAsn1Error:
        ret["errmsg"] = f"Probable malformed OID {oid}"
        return ret

    if errorIndication:
        ret["errmsg"] = str(errorIndication)
        return ret
    if errorStatus:
        ret["errmsg"] = str(errorStatus.prettyPrint())
        return ret
    for varBind in varBinds:
        ret["pretty"] = ' = '.join([x.prettyPrint() for x in varBind])
        ret["oid"] = varBind[0]
        ret["v"] = varBind[1]
    ret["err"] = 0
    return ret


def do_snmpd_disk(hostname, hostip, snmp_community):
    buf = ""
    snmp_disk_oid = []
    i = 0
    while i < 100:
        ret = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.3.{i}', hostip, 161, snmp_community)
        if ret['err'] == 0:
            partname = str(ret['v'])
            oid = str(ret['oid'])
            if partname[0] == '/':
                # print(f"DEBUG: SNMP found disk {partname}")
                snmp_disk_oid.append(i)
        else:
            if 'errmsg' in ret:
                if 'timeout' in ret['errmsg']:
                    return buf
        i += 1
    buf += '[df]\n'
    for oid in snmp_disk_oid:
        # print(f"DEBUG: SNMP DISK check {oid}")
        disk_name = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.3.{oid}', hostip, 161, snmp_community)
        if disk_name['err'] != 0:
            buf += f'ERROR getting {oid}\n'
            continue
        dname = disk_name['v']
        disk_block_size = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.4.{oid}', hostip, 161, snmp_community)
        if disk_block_size['err'] != 0:
            buf += f'ERROR getting {dname} block size\n'
            continue
        disk_total = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.5.{oid}', hostip, 161, snmp_community)
        if disk_total['err'] != 0:
            buf += f'ERROR getting {dname} total size\n'
            continue
        disk_used = snmp_get(f'.1.3.6.1.2.1.25.2.3.1.6.{oid}', hostip, 161, snmp_community)
        if disk_used['err'] != 0:
            buf += f'ERROR getting {dname} used size\n'
            continue
        dbs = int(disk_block_size['v'])
        dt = int(disk_total['v'])
        du = int(disk_used['v'])
        dt *= int(dbs / 1024)
        du *= int(dbs / 1024)
        df = dt - du
        percent = int(100 * du / dt)
        buf += f'{dname}\t{dt}\t{du}\t{df}\t{percent}%\t{dname}\n'
    return buf


def do_snmpd_memory(hostname, hostip, snmp_community):
    ret = {}
    ret['snmp'] = ""
    swap_total = snmp_get('.1.3.6.1.4.1.2021.4.3.0', hostip, 161, snmp_community)
    if swap_total["err"] != 0:
        ret['snmp'] = f'&red do_snmpd_memory: error with swap_total: {swap_total["errmsg"]}\n'
        return ret
    ret['snmp'] += swap_total["pretty"]
    swap_free = snmp_get('.1.3.6.1.4.1.2021.4.4.0', hostip, 161, snmp_community)
    if swap_free["err"] != 0:
        ret['snmp'] = f'&red do_snmpd_memory: error with swap_free: {swap_free["errmsg"]}\n'
        return ret
    memory_total = snmp_get('.1.3.6.1.4.1.2021.4.5.0', hostip, 161, snmp_community)
    if memory_total["err"] != 0:
        ret['snmp'] = f'&red do_snmpd_memory: error with memory_total: {memory_total["errmsg"]}\n'
        return ret
    memory_used = snmp_get('.1.3.6.1.4.1.2021.4.6.0', hostip, 161, snmp_community)
    memory_free = snmp_get('.1.3.6.1.4.1.2021.4.11.0', hostip, 161, snmp_community)
    memory_shared = snmp_get('.1.3.6.1.4.1.2021.4.13.0', hostip, 161, snmp_community)
    memory_buffered = snmp_get('.1.3.6.1.4.1.2021.4.14.0', hostip, 161, snmp_community)
    memt = memory_total['v']
    memf = memory_free['v']
    memu = memory_used['v']
    mems = memory_shared['v']
    # no .1.3.6.1.4.1.2021.4.14.0 on OpenBSD
    if "v" in memory_buffered:
        memb = memory_buffered['v']
    else:
        memb = 0
    ret['buf'] = f'[free]\nMem:\t{memt}\t{memu}\t{memf}\t{mems}\t{memb}\t{memf}\n'
    ret['snmp'] = '&green DID memory OK\n'
    return ret


def do_snmpd_client(hostname, hostip, snmp_columns, snmp_community):
    dret = {}
    color = 'green'
    status = ""
    # TODO check linux
    sysdscr = snmp_get('.1.3.6.1.2.1.1.1.0', hostip, 161, snmp_community)
    err = sysdscr['err']
    if err == 0:
        osname = str(sysdscr['v']).split(' ')[0].lower()
        buf = f'client {hostname}.{osname} {osname}\n'
        buf += f"[uname]\n{sysdscr['v']}\n"
        status += sysdscr['pretty']
        status += '\n'
    else:
        buf = f'client {hostname}.unknow unknow\n'
        color = 'red'
        status += f"&red do_snmpd_client: error with sysdscr: {sysdscr['errmsg']}\n"
    if 'memory' in snmp_columns:
        ret = do_snmpd_memory(hostname, hostip, snmp_community)
        if 'buf' in ret:
            buf += ret['buf']
        if 'snmp' in ret:
            status += ret['snmp']
    if 'disk' in snmp_columns:
        buf += do_snmpd_disk(hostname, hostip, snmp_community)
    buf += '[end]\n'
    dret["data"] = buf
    dret['txt'] = status
    dret['color'] = color
    return dret


@app.task
def do_snmp(hostname, hostip, snmp_community, snmp_columns, oids):
    ts_start = time.time()
    dret = {}
    dret["type"] = 'snmp'
    dret["column"] = 'snmp'
    dret["hostname"] = hostname
    color = 'green'
    buf = ''
    print(f"DEBUG: SNMP for {hostname} hostip={hostip} snmp_columns={snmp_columns} oids={oids}")
    if len(snmp_columns) > 0:
        ret = do_snmpd_client(hostname, hostip, snmp_columns, snmp_community)
        buf += ret["txt"]
        dret["data"] = ret["data"]
        color = setcolor(ret["color"], color)
        result = {}
        for rrd in oids:
            if rrd not in result:
                result[rrd] = {}
            # print(f"DEBUG: handle SNMP rrd={rrd}")
            for obj in oids[rrd]:
                # print(f"DEBUG: handle SNMP rrd={rrd} obj={obj}")
                rrdcolor = 'green'
                rrdbuf = ""
                dsnames = []
                values = []
                dsspecs = []
                for oid in oids[rrd][obj]:
                    # print(f"DEBUG: handle rrd={rrd} oid={oid}")
                    dsnames.append(oid['dsname'])
                    dsspecs.append(oid['dsspec'])
                    ret = snmp_get(oid['oid'], hostip, 161, snmp_community)
                    if ret['err'] == 0:
                        buf += f"&green did {rrd} {obj} {oid['oid']} {oid['dsname']} value={ret['v']}\n"
                        rrdbuf += f"&green did {rrd} {obj} {oid['oid']} {oid['dsname']} value={ret['v']}\n"
                        values.append(str(ret["v"]))
                    else:
                        buf += f"&red did {rrd} {obj} {oid['oid']} {ret['errmsg']}\n"
                        rrdbuf += f"&red did {rrd} {obj} {oid['oid']} {ret['errmsg']}\n"
                        color = 'red'
                        rrdcolor = 'red'
                # print(f"DEBUG: value={values}")
                r = {}
                r["dsnames"] = ":".join(dsnames)
                r["values"] = ":".join(values)
                r["dsspecs"] = dsspecs
                r["status"] = rrdbuf
                r["color"] = rrdcolor
                result[rrd][obj] = r
        dret["rrds"] = result
    dret["color"] = color
    now = time.time()
    dret["txt"] = f"{xytime(now)} - snmp\n" + buf
    test_duration = now - ts_start
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    return dret


# xssh://[username][:password]@target[:port][;edkey=path][;rsakey=path][;ping:target]
class xssh:
    def __init__(self, hostname, url):
        print(f'DEBUG: init with {url}')
        self.dret = {}
        self.dret["type"] = 'tssh'
        self.dret["column"] = 'tssh'
        self.dret["hostname"] = hostname
        self.dret["txt"] = ""
        self.dret["data"] = None
        self.dret["color"] = 'green'
        if hostname is None or url is None:
            self.dret['color'] = 'red'
            return
        url.rstrip('\n')
        self.hdata = ""
        self.actions = []
        self.hostname = hostname
        self.port = 22
        self.timeout = 60
        self.key = None
        self.one_by_one = False
        self.sudo = False
        tokens = url.split(';')
        if len(tokens) <= 1:
            self.dret['color'] = 'red'
            self.dret['txt'] = 'No tests'
            return
        base = tokens.pop(0).replace("tssh://", '')
        btoks = base.split('@')
        if len(btoks) <= 1:
            self.dret['color'] = 'red'
            self.dret['txt'] = f'Invalid user@host {base}'
            return
        self.username = btoks[0]
        self.chostname = btoks[1]
        if self.chostname == '':
            self.dret['color'] = 'red'
            self.dret['txt'] = 'hostname is empty'
            return
        # handle ssh port
        if ':' in self.chostname:
            htoks = self.chostname.split(':')
            if len(htoks) != 2:
                self.dret['color'] = 'red'
                self.dret['txt'] = 'ERROR: invalid hostname:port'
                return
            self.chostname = htoks[0]
            try:
                port = int(htoks[1])
            except ValueError:
                self.dret['color'] = 'red'
                self.dret['txt'] = f'ERROR: port {htoks[1]} is not a number'
                return
            if port < 0 or port > 65535:
                self.dret['color'] = 'red'
                self.dret['txt'] = f'ERROR: port {port} is out of range'
                return
            self.port = port
        self.password = None
        self.ts_start = time.time()
        if ':' in self.username:
            usertok = self.username.split(':')
            self.username = usertok.pop(0)
            self.password = ':'.join(usertok)
            self.hdata += "&clear password found\n"
        if self.username == '':
            self.dret['color'] = 'red'
            self.dret['txt'] = 'ERROR: username is empty'
            return
        if self.password == '':
            self.dret['color'] = 'red'
            self.dret['txt'] = 'ERROR: password is empty'
            return
        for token in tokens:
            if not self.check_token(token):
                self.dret['color'] = 'red'
        print(f'DEBUG: RSSH init with user={self.username} chostname={self.chostname}')

    def check_token(self, token):
        print(f'DEBUG: RSSH check token={token}')
        if token[0:8] == 'timeout=':
            ktoken = token.split("=")
            if len(ktoken) != 2:
                self.dret["txt"] += f"status+10m {self.hostname}.tssh red\n&red Wrong timeout token {token}\n"
                return False
            try:
                timeout = int(ktoken[1])
            except ValueError:
                self.dret['color'] = 'red'
                self.dret['txt'] = f'ERROR: timeout {ktoken[1]} is not a number'
                return False
            if timeout < 0:
                self.dret['color'] = 'red'
                self.dret['txt'] = f'ERROR: timeout {timeout} is out of range'
                return
            self.timeout = timeout
            return True
        if token[0:6] == 'edkey=':
            ktoken = token.split("=")
            if len(ktoken) != 2:
                self.dret["txt"] += f"status+10m {self.hostname}.tssh red\n&red Wrong key token {token}\n"
                return False
            keypath = ktoken[1]
            try:
                self.key = paramiko.Ed25519Key.from_private_key_file(keypath)
            except FileNotFoundError as e:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to load {keypath}: {str(e)}\n"
                return False
            except paramiko.ssh_exception.SSHException as e:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to load {keypath}: {str(e)}\n"
                return False
            except PermissionError as e:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to load {keypath}: {str(e)}\n"
                return False
            self.hdata += f"Loaded {keypath}\n"
            return True
        if token[0:7] == 'rsakey=':
            ktoken = token.split("=")
            if len(ktoken) != 2:
                self.dret["txt"] += f"status+10m {self.hostname}.tssh red\n&red Wrong key token {token}\n"
                return False
            keypath = ktoken[1]
            try:
                self.key = paramiko.RSAKey.from_private_key_file(keypath)
            except FileNotFoundError as e:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to load {keypath}: {str(e)}\n"
                return False
            except paramiko.ssh_exception.SSHException as e:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to load {keypath}: {str(e)}\n"
                return False
            except PermissionError as e:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to load {keypath}: {str(e)}\n"
                return False
            self.dret["txt"] += f"Loaded {keypath}\n"
            return True
        if token[0:5] == 'ping:':
            ktoken = token.split(":")
            if len(ktoken) != 2:
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red invalid ping\n"
                return False
            if ktoken[1] == '':
                self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red empty target\n"
                return False
            action = {}
            action['type'] = 'ping'
            action['target'] = ktoken[1]
            self.actions.append(action)
            return True
        if token == 'client':
            action = {}
            action['type'] = 'client'
            self.actions.append(action)
            return True
        if token == 'hack1by1':
            self.one_by_one = True
            return True
        if token == 'sudo':
            self.sudo = True
            return True
        print(f"DEBUG: RSSH unknow keyword {token}")
        self.dret["txt"] = f"status+11m {self.hostname}.tssh red\n&red unknown parameter {token}\n"
        return False

    def run(self, state = None):
        print(f'DEBUG: RSSH run state={state}')
        if len(self.actions) == 0:
            # print('DEBUG: RSSH no action setup')
            self.dret['color'] = 'red'
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red no actions"
            return self.dret
        if self.dret['color'] == 'red':
            # print('DEBUG: RSSH already red')
            # print(self.dret)
            return self.dret
        client = SSHClient()
        client.load_system_host_keys()
        # print('DEBUG: RSSH run2')
        # TODO permit to choose the policy
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        # logger remove the paramiko.ssh_exception.IncompatiblePeer log
        # https://github.com/paramiko/paramiko/pull/2157
        # TODO do something better
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        try:
            client.connect(self.chostname, username=self.username, password=self.password, timeout=self.timeout, port=self.port, pkey=self.key)
        except socket.gaierror as e:
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to connect on {self.chostname}: {str(e)}\n"
            self.dret["color"] = 'red'
            return self.dret
        # Authentication failed
        except paramiko.ssh_exception.SSHException as e:
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to connect(SSHException) on {self.chostname}: {str(e)}\n"
            self.dret["color"] = 'red'
            return self.dret
        # TODO when I got that ? how to test
        except PermissionError as e:
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to setup for {self.chostname}: {str(e)}\n"
            self.dret["color"] = 'red'
            return self.dret
        # connexion refused
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to connect(NoValidConnectionsError) on {self.chostname}: {str(e)}\n"
            self.dret["color"] = 'red'
            return self.dret
        except TimeoutError as e:
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to connect(TimeoutError) on {self.chostname}: {str(e)}\n"
            self.dret["color"] = 'red'
            return self.dret
        except socket.timeout as e:
            self.dret["txt"] = f"status+10m {self.hostname}.tssh red\n&red Failed to connect(TimeoutError) on {self.chostname}: {str(e)}\n"
            self.dret["color"] = 'red'
            return self.dret

        if state == 'client-upload':
            ret = self.upload(client)
            client.close()
            return ret

        if state == 'client-chmod':
            ret = self.chmod(client)
            client.close()
            return ret

        if state == 'client-run':
            ret = self.doclient(client)
            client.close()
            return ret


        for action in self.actions:
            acolor = 'green'
            # action client
            if action['type'] == 'client':
                # handle case where sftp-server is not present
                transport = client.get_transport()
                try:
                    with transport.open_channel(kind='session') as channel:
                        file_data = open('/usr/bin/xython-client', 'rb').read()
                        channel.exec_command('cat > /tmp/xython-client')
                        channel.sendall(file_data)
                    with transport.open_channel(kind='session') as channel:
                        channel.exec_command('chmod 770 /tmp/xython-client')
                    rcmd = '/tmp/xython-client'
                    if self.sudo:
                        rcmd = 'sudo /tmp/xython-client'
                    stdin, stdout, stderr = client.exec_command(rcmd)
                except paramiko.ssh_exception.SSHException as e:
                    test_duration = time.time() - self.ts_start
                    self.dret["color"] = 'red'
                    self.dret["txt"] = f'ERROR: Failed to setup xython-client {str(e)}'
                    self.dret["txt"] += f"\nSeconds: {test_duration}\n"
                    client.close()
                    return self.dret
                errorlog = '"'.join(stderr.readlines())
                if errorlog:
                    acolor = 'yellow'
                self.dret["txt"] += '<fieldset><legend>error log</legend>\n' + errorlog + "\n</fieldset>"
                self.dret["data"] = ''.join(stdout.readlines())
            if action['type'] == 'ping':
                try:
                    stdin, stdout, stderr = client.exec_command(f'ping -c4 {action["target"]}')
                except paramiko.ssh_exception.SSHException as e:
                    test_duration = time.time() - self.ts_start
                    self.dret["color"] = 'red'
                    self.dret["txt"] = f'ERROR: Failed to execute {action["type"]} {str(e)}'
                    self.dret["txt"] += f"\nSeconds: {test_duration}\n"
                    client.close()
                    return self.dret
                errorlog = '"'.join(stderr.readlines())
                if errorlog:
                    acolor = 'yellow'
                if stdout.channel.recv_exit_status() != 0:
                    acolor = 'red'
                self.dret["txt"] += f'&{acolor}ping {action["target"]}\n<fieldset><legend>output log</legend>\n' + ''.join(stdout.readlines()) + "\n</fieldset>"
                self.dret["txt"] += '<fieldset><legend>error log</legend>\n' + errorlog + "\n</fieldset>"
            self.dret["color"] = setcolor(acolor, self.dret["color"])
        client.close()

        test_duration = time.time() - self.ts_start
        # self.dret["txt"] = f'status+10m {self.hostname}.tssh {self.dret["color"]}\n' + self.hdata + self.dret["txt"]
        self.dret["txt"] = self.hdata + '\n' + self.dret["txt"]
        self.dret["txt"] += f"\nSeconds: {test_duration}\n"
        return self.dret

    def upload(self, client):
        transport = client.get_transport()
        try:
            with transport.open_channel(kind='session') as channel:
                file_data = open('/usr/bin/xython-client', 'rb').read()
                channel.exec_command('cat > /tmp/xython-client')
                channel.sendall(file_data)
                self.dret["txt"] += 'Upload OK\n<br>'
        except paramiko.ssh_exception.SSHException as e:
            self.dret["color"] = 'red'
            self.dret["txt"] = f'ERROR: Failed to upload xython-client {str(e)}'
            return False
        return True

    def chmod(self, client):
        transport = client.get_transport()
        try:
            with transport.open_channel(kind='session') as channel:
                channel.exec_command('chmod 770 /tmp/xython-client')
                self.dret["txt"] += 'Chmod OK\n<br>'
        except paramiko.ssh_exception.SSHException as e:
            self.dret["color"] = 'red'
            self.dret["txt"] += f'ERROR: Failed to chmod xython-client {str(e)}'
            return False
        return True

    def doclient(self, client):
        try:
            stdin, stdout, stderr = client.exec_command('/tmp/xython-client')
        except paramiko.ssh_exception.SSHException as e:
            self.dret["color"] = 'red'
            self.dret["txt"] += f'ERROR: Failed to run xython-client {str(e)}'
            return False
        errorlog = '"'.join(stderr.readlines())
        if errorlog:
            self.dret["color"] = setcolor('yellow', self.dret["color"])
        self.dret["txt"] += '<fieldset><legend>error log</legend>\n' + errorlog + "\n</fieldset>"
        self.dret["data"] = ''.join(stdout.readlines())
        return True


@app.task
def do_tssh(hostname, urls):
    tssh = xssh(hostname, urls[0])
    if tssh.one_by_one:
        tssh.run(state = 'client-upload')
        tssh.run(state = 'client-chmod')
        tssh.run(state = 'client-run')
        return tssh.dret
    return tssh.run()


@app.task
def task_fail():
    raise ValueError("FAIL")

@app.task
def ping(hostname, t, doipv4, doipv6):
    ts_start = time.time()
    dret = {}
    dret["type"] = 'conn'
    dret["column"] = 'conn'
    dret["hostname"] = hostname
    dret["txt"] = ""
    dret["color"] = 'green'

    env = os.environ
    env["LANG"] = 'C'
    env["LC_ALL"] = 'C'
    # always ping with -c>1, this detect some error in switch trunking (like 1 packet out of x is bad)
    if not doipv4 and not doipv6:
        ret = subprocess.run(["ping", "-c", "2", t], capture_output=True)
        if ret.returncode != 0:
            dret["color"] = 'red'
        hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
        dret["txt"] += hdata
        dret["txt"] += "\nTested via ping\n"
        re_rtts = re.search(r"[0-9]+.[0-9]*/[0-9]+.[0-9]*/[0-9]+.[0-9]*/", hdata)
        if re_rtts is not None:
            rtts = re_rtts.group(0)
            tokens = rtts.split('/')
            if len(tokens) == 4:
                rtt_min = tokens[0]
                dret["rtt_avg"] = tokens[1]
                rtt_max = tokens[2]
    if doipv4:
        ret = subprocess.run(["ping", "-4", "-c", "2", t], capture_output=True)
        if ret.returncode != 0:
            dret["color"] = 'red'
        hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
        dret["txt"] += hdata
        dret["txt"] += "\nTested via ping -4\n"
        re_rtts = re.search(r"[0-9]+.[0-9]*/[0-9]+.[0-9]*/[0-9]+.[0-9]*/", hdata)
        if re_rtts is not None:
            rtts = re_rtts.group(0)
            tokens = rtts.split('/')
            if len(tokens) == 4:
                rtt_min = tokens[0]
                dret["rtt_avg"] = tokens[1]
                rtt_max = tokens[2]
    if doipv6:
        ret = subprocess.run(["ping", "-6", "-c", "2", t], capture_output=True)
        if ret.returncode != 0:
            dret["color"] = 'red'
        hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
        dret["txt"] += hdata
        dret["txt"] += "\nTested via ping -6\n"
    test_duration = time.time() - ts_start
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    dret["timing"] = test_duration
    return dret


@app.task
def dohttp(hostname, urls, column):
    ts_start = time.time()
    color = "green"
    hdata = ""
    httpstate = ""
    httpcount = 0
    dret = {}
    dret["certs"] = {}
    for url in urls:
        options = ""
        check_content = None
        verify = True
        timeout = 30
        headers = {}
        headers["User-Agent"] = f'xython xythonnet/{version("xython")}'
        need_httpcode = 200
        bad_httpcode = None
        need_redirect = True
        hdata += f'<fieldset><legend>{url}</legend>'
        # print(f'DEBUG: dohttp: check {url}')
        tokens = url.split(';')
        url = tokens.pop(0)
        # detect proxy
        proxies = None
        pret = re.search("(http://.*)/(https?://.*)", url)
        if pret:
            ps = pret.group(1)
            url = pret.group(2)
            proxies = { "http": ps, "https": ps }
        for token in tokens:
            cmds = token.split('=')
            cmd = cmds[0]
            if cmd == 'timeout':
                timeout = int(cmds[1])
                options += f"timeout={cmds[1]}"
            if cmd == 'verify':
                v = cmds[1]
                if v == '0':
                    verify = False
                elif v == '1':
                    verify = True
                else:
                    verify = cmds[1]
                options += f"verify={cmds[1]}"
            elif cmd == 'cont':
                check_content = cmds[1].replace('[[:space:]]', '\\s')
            elif cmd == 'httpcode':
                # TODO check it is an integer or regex
                need_httpcode = cmds[1]
            elif cmd == 'badhttpcode':
                # TODO check it is an integer or regex
                bad_httpcode = cmds[1]
            elif cmd == 'noredirect':
                need_redirect = False
            else:
                options += f"unknow={token}"
        if httpcount > 0:
            httpstate += "; "
        httpcount += 1
        cret = None
        # self.debug("\tDEBUG: http %s" % url)
        try:
            r = requests.get(url, headers=headers, verify=verify, timeout=timeout, stream=True, proxies=proxies, allow_redirects=need_redirect)
            if verify and 'https' in url and r.raw.connection is not None and r.raw.connection.sock is not None:
                cret = show_cert(r.raw.connection.sock.getpeercert(), hostname)
            hdata += f"&green {url} - OK\n\n"
            scode = str(r.status_code)
            sneed = str(need_httpcode)
            sbad = str(bad_httpcode)
            if re.match(sbad, scode):
                color = "red"
                hdata += f"&red {r.status_code} {r.reason} (bad code={bad_httpcode})\n"
            elif re.match(sneed, scode):
                hdata += f"&green {r.status_code} {r.reason}\n"
            else:
                color = "red"
                hdata += f"&red {r.status_code} {r.reason} (want code={need_httpcode})\n"
            for header in r.headers:
                hdata += "%s: %s\n" % (header, r.headers[header])
            httpstate += "OK"
            if check_content:
                content = r.content.decode('utf8')
                if re.search(check_content, content):
                    hdata += f'&green pattern {check_content} found\n'
                else:
                    color = "red"
                    hdata += f'&red pattern {check_content} not found\n'
        except requests.exceptions.Timeout as e:
            color = "red"
            hdata += f"&red {url} - TIMEOUT {str(e)}\n"
            httpstate += "Timeout"
        except requests.exceptions.RequestException as e:
            color = "red"
            if re.search('Connection refused', str(e)):
                httpstate += 'Connection refused'
                hdata += f"&red {url} - Connection refused\n"
            else:
                # TODO find something better to put readable error message
                emsg = str(e).replace(": ", ":<br>")
                hdata += f"&red {url} - KO<br>\n{emsg}\n"
                httpstate += "KO"
#        except requests.exceptions.ConnectionError as e:
#            color = "red"
#            if re.search('Connection refused', str(e)):
#                httpstate += 'Connection refused'
#                hdata += f"&red {url} - Connection refused\n"
#            else:
#                hdata += f"&red {url} - KO\n"
#                httpstate += "KO"
        if cret:
            hdata += cret["txt"] + "\n\n"
            dret["certs"][url] = cret
        if options != "":
            hdata += f"xython options: {options}\n"
        hdata += '</fieldset><br>'
    now = time.time()
    fdata = f"{xytime(now)}: {httpstate}\n"
    test_duration = now - ts_start
    dret["hostname"] = hostname
    dret["color"] = color
    dret["txt"] = fdata + hdata
    dret["timing"] = test_duration
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    dret["type"] = 'http'
    dret["column"] = 'http'
    return dret


def hex_to_binary(hs):
    # print("====================")
    hexs = ""
    i = 0
    while i < len(hs):
        c = hs[i]
        # print(f"DEBUG: current {c} i={i} len={len(hs)}")
        if c == '\\':
            if i + 1 >= len(hs):
                return None
            C = hs[i + 1]
            if C == 'x':
                if i + 3 >= len(hs):
                    return None
                v = hs[i + 2:i + 4]
                # print(f"DEBUG: value is {v}")
                hexs += f'{v} '
                i += 4
                continue
            elif C == 'r':
                hexs += "0D "
            elif C == 'n':
                hexs += "0A "
            elif C == 't':
                hexs += "09 "
            else:
                # TODO
                print(f"DEBUG: invalid {C}")
                return None
            i += 2
        else:
            hexs += f'{ord(c):x} '
            i += 1
    # print(f"DEBUG: final {hexs}")
    # print(f"DEBUG: final {bytes.fromhex(hexs)}")
    # print(f"DEBUG: final {bytes.fromhex(hexs).decode('UTF8')}")
    return bytes.fromhex(hexs)


# compare binary b and xython protocol binary format e
def hex_compare(b, e):
    # print("==========================")
    bh = hex_to_binary(e)
    # print(f"DEBUG: compare {bh} and {b}")
    # reduce lengh of b
    b = b[:len(bh)]
    # print(f"DEBUG: compare {bh} and {b}")
    if bh == b:
        return True
    return False


# https://stackoverflow.com/questions/6464129/certificate-subject-x-509
def get_cn(t):
    r = ""
    unk = ""
    for p in t:
        # if len(p) > 1:
        #    unk += "length "
        # TODO: does this can exists ?
        if p[0][0] == 'countryName':
            r += f"/C={p[0][1]}"
            continue
        if p[0][0] == 'stateOrProvinceName':
            r += f"/ST={p[0][1]}"
            continue
        if p[0][0] == 'organizationName':
            r += f"/O={p[0][1]}"
            continue
        if p[0][0] == 'commonName':
            r += f"/CN={p[0][1]}"
            continue
        if p[0][0] == 'localityName':
            r += f"/L={p[0][1]}"
            continue
        if p[0][0] == 'organizationalUnitName':
            r += f"/OU={p[0][1]}"
            continue
        if p[0][0] == 'organizationIdentifier':
            r += f"/OI={p[0][1]}"
            continue
        if p[0][0] == 'serialNumber':
            r += f"/SN={p[0][1]}"
            continue
        if p[0][0] == 'surname':
            r += f"/SN={p[0][1]}"
            continue
        unk += str(p)
        print(f"UNK={p}")
    ret = {}
    ret["unk"] = unk
    ret["name"] = r
    return ret


def show_cert(cert, hostname):
    cret = {}
    cret['txt'] = ''
    cret['expire'] = None
    if 'subject' not in cert:
        print("===================================")
        print("ERROR no subject")
        print(f"cert={cert}")
        cret["txt"] = f"Failed to get certificate for {hostname}"
        return cret
    else:
        ret = get_cn(cert['subject'])
    if "name" not in ret:
        cret["txt"] = f"Failed to get certificate for {hostname}"
        return cret
    cret["txt"] = f"Server certificate:\n\tSubject: {ret['name']}\n"
    cret["txt"] += f"\tstart date: {cert['notBefore']}\n"
    cret["txt"] += f"\texpire date:{cert['notAfter']}\n"
    ret = get_cn(cert['issuer'])
    cret["txt"] += f"\tissuer:{ret['name']}\n"
    now = time.time()
    date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    expire = date.timestamp()
    expire_days = int((expire - now) / 86400)
    cret["txt"] += f"Expire in {expire_days} days\n"
    cret["expire"] = expire_days
    # TODO key size
    # TODO signature used
    # TODO cipher used

    return cret


def do_generic_proto_ssl(hostname, address, protoname, port, url, p_send, p_expect, p_options):
    ts_start = time.time()
    dret = {}
    dret["color"] = 'red'
    dret['column'] = protoname
    dret['certs'] = {}
    thostname = hostname
    tokens = url.split(':')
    timeout = 60
    i = 1
    verify = ssl.CERT_REQUIRED
    while i < len(tokens):
        option = tokens[i]
        # print(f"DEBUG: generic proto ssl: check {option}")
        if tokens[i].isdigit():
            port = int(tokens[i])
        elif tokens[i][0:7] == 'column=':
            hs = tokens[i].split('=')
            dret['column'] = hs[1]
        elif tokens[i][0:8] == 'timeout=':
            hs = tokens[i].split('=')
            try:
                timeout = int(hs[1])
            except ValueError:
                dret['txt'] = '&red invalid timeout'
                return dret
        elif tokens[i][0:7] == 'verify=':
            verify = ssl.CERT_NONE
            # print(f"DEBUG: no certificate check for {thostname}")
        elif tokens[i][0:9] == 'hostname=':
            hs = tokens[i].split('=')
            thostname = hs[1]
        else:
            dret['txt'] = '&red ERROR: unknow token {tokens[i]}'
            return dret
        i += 1

    if port is None:
        dret['txt'] = '&red ERROR: port is None'
        return dret
    if port < 0 or port > 65535:
        dret['txt'] = '&red ERROR: port is out of range'
        return dret

    # print(f"GENERIC TLS PROTOCOLS addr={address} port={port} proto={protoname} url={url} thostname={thostname} timeout={timeout}")

    try:
        context = ssl.create_default_context()
        context.check_hostname = not (verify == ssl.CERT_NONE)
        context.verify_mode = verify
        sock = socket.create_connection((address, port))
        sock.settimeout(timeout)
        ssock = context.wrap_socket(sock, server_hostname=thostname)
        if p_send:
            if '\\x' in p_send:
                ssock.write(hex_to_binary(p_send))
            else:
                ssock.write(p_send.encode("UTF8"))
        if p_expect or (p_options is not None and 'banner' in p_options):
            buf = ssock.read(1024)
            banner = buf.decode("UTF8")
        if p_expect:
            if '\\x' in p_send:
                if hex_compare(buf, p_expect):
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nbinary banner ok\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nbinary banner ko wanted {p_expect} got {buf}\n\n"
            else:
                if p_expect in banner:
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n{banner}\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n{banner}\n\nWanted {p_expect}\n\n"
        else:
            dret["color"] = 'green'
            dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nconnected successfully on {address}\n"
        if context.check_hostname:
            cret = show_cert(ssock.getpeercert(), hostname)
            dret["txt"] += cret["txt"] + '\n\n'
            dret["certs"][url] = cret
        else:
            dret["txt"] += "Cannot test certificate since verify=0\n\n"
    except socket.gaierror as e:
        dret["txt"] = f"Service {protoname} on {hostname} is KO\n\n{str(e)}n\n"
    except ssl.SSLCertVerificationError as e:
        dret["txt"] = f"Service {protoname} on {hostname} is KO\n\n{str(e)}\n\n"
    except ConnectionRefusedError:
        dret["txt"] = "Connection refused\n\n"
    except OSError as e:
        # errno 113 No route to host
        dret["txt"] = str(e) + "\n\n"
    dret["txt"] += f"\nSeconds: {time.time() - ts_start}\n"
    # print(f"GENERIC TLS PROTOCOLS addr={address} port={port} proto={protoname} url={url} thostname={thostname} ret={dret}")
    return dret


@app.task
def do_generic_proto(hostname, address, protoname, port, urls, p_send, p_expect, p_options):
    ts_start = time.time()
    dret = {}
    dret["hostname"] = hostname
    dret["type"] = protoname
    dret["column"] = protoname
    dret["color"] = 'green'
    dret["txt"] = ""
    dret["certs"] = {}
    for url in urls:
        dret["txt"] += f'<fieldset><legend>{url}</legend>\n'
        if p_options and "ssl" in p_options:
            ret = do_generic_proto_ssl(hostname, address, protoname, port, url, p_send, p_expect, p_options)
            for u in ret["certs"]:
                dret["certs"][u] = ret["certs"][u]
        else:
            ret = do_generic_proto_notls(hostname, address, protoname, port, url, p_send, p_expect, p_options)
        dret["color"] = setcolor(ret["color"], dret["color"])
        dret["txt"] += ret["txt"]
        dret["txt"] += '<br></fieldset><br>\n'
        if 'column' in ret:
            dret["column"] = ret["column"]
    test_duration = time.time() - ts_start
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    if dret['color'] == 'green':
        dret["txt"] = f"{xytime(ts_start)}: OK\n" + dret["txt"]
    else:
        dret["txt"] = f"{xytime(ts_start)}: KO\n" + dret["txt"]
    dret["timing"] = test_duration
    return dret


def do_generic_proto_notls(hostname, address, protoname, port, url, p_send, p_expect, p_options):
    dret = {}
    dret["color"] = 'red'
    dret['column'] = protoname
    timeout = 60

    tokens = url.split(':')
    # print(f"DEBUG: {url} {tokens} {len(tokens)} p_send={p_send} p_expect={p_expect}")
    i = 1
    while i < len(tokens):
        option = tokens[i]
        print(f"DEBUG: generic proto notls: check {option}")
        if option.isdigit():
            port = int(option)
        elif tokens[i][0:8] == 'timeout=':
            hs = tokens[i].split('=')
            try:
                timeout = int(hs[1])
            except ValueError:
                dret['txt'] = '&red invalid timeout'
                return dret
        else:
            dret['txt'] = '&red ERROR: unknow token {tokens[i]}'
            return dret
        i += 1

    try:
        s = socket.socket()
        s.connect((address, port))
        s.settimeout(timeout)
        if p_send:
            # HACK 554 5.5.0 Error: SMTP protocol synchronization
            if protoname in ['smtp', 'smtps']:
                time.sleep(1)
            if '\\x' in p_send:
                s.send(hex_to_binary(p_send))
            else:
                s.send(p_send.encode("UTF8"))
        if p_expect or (p_options is not None and 'banner' in p_options):
            buf = s.recv(1024)
            banner_decode = False
            try:
                banner = buf.decode("UTF8")
                banner_decode = True
            except UnicodeDecodeError:
                print(f"DEBUG: banner decode error for {hostname}:{protoname}")
            if not banner_decode:
                try:
                    banner = buf.decode("UTF8", 'surrogateescape')
                except UnicodeDecodeError:
                    print(f"DEBUG: banner decode22 error for {hostname}:{protoname}")
                    s.close()
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nFail to decode banner\n\n"
                    return dret
        if p_expect:
            if '\\x' in p_send:
                if hex_compare(buf, p_expect):
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nbinary banner ok\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nbinary banner ko GOT {buf}\n\n"
            else:
                if p_expect in banner:
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n{banner}\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n{banner}\n\n"
        else:
            dret["color"] = 'green'
            dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nconnected successfully on {address}\n"
        s.close()
    except ConnectionError as e:
        dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nFailed to connect to {address} {str(e)}\n\n"
    except OSError as error:
        dret["txt"] = f"Service {protoname} on {hostname} is ko\n\n" + str(error) + "\n\n"
    return dret
