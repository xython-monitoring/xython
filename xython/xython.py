#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import asyncio
import bz2
import hashlib
import logging
import os
import pytz
import time
import re
import ssl
import sys
from random import randint
import resource
import shutil
import socket
from importlib.metadata import version
try:
    import pika
    has_pika = True
except ImportError:
    has_pika = False
try:
    import rrdtool
    has_rrdtool = True
except ImportError:
    has_rrdtool = False
import sqlite3
from .xython_tests import task_fail
from .xython_tests import ping
from .xython_tests import dohttp
from .xython_tests import do_tssh
from .xython_tests import do_snmp
from .xython_tests import do_generic_proto
import celery
from .common import xytime
from .common import xytime_
from .common import xyts
from .common import xyts_
from .common import event_thisyear
from .common import event_lastyear
from .common import event_thismonth
from .common import event_lastmonth
from .common import event_thisweek
from .common import event_lastweek
from .common import event_yesterday
from .common import event_today
from .common import xyevent
from .common import xyevent_to_ts
from .common import gcolor
from .common import gif
from .common import setcolor
from .common import tokenize
from .common import xydhm
from .common import xydelay
from .common import COLORS
from .common import is_valid_hostname
from .common import is_valid_color
from .common import is_valid_column

from .rules import xy_rule_disks
from .rules import xy_rule_port
from .rules import xy_rule_proc
from .rules import xy_rule_mem
from .rules import xy_rule_cpu
from .rules import xy_rule_sensors
from .rules import SENSOR_DISABLE

RRD_COLOR = ["0000FF", "FF0000", "00CC00", "FF00FF", "555555", "880000", "000088", "008800",
             "008888", "888888", "880088", "FFFF00", "888800", "00FFFF", "00FF00", "AA8800",
             "AAAAAA", "DD8833", "DDCC33", "8888FF", "5555AA", "B428D3", "FF5555", "DDDDDD",
             "AAFFAA", "AAFFFF", "FFAAFF", "FFAA55", "55AAFF", "AA55FF"]
COLUMN_COLOR = 4


class xy_protocol:
    def __init__(self):
        self.send = None
        self.expect = None
        self.port = None
        self.options = None


class xy_host:
    def __init__(self, name, xclass='unset'):
        self.last_ping = 0
        self.name = name
        self.aliases = []
        self.tests = []
        self.hostip = ""
        # False => use name, True use host_ip
        self.use_ip = False
        self.rules = {}
        self.rhcnt = 0
        self.hist_read = False
        self.tags = None
        self.tags_read = False
        self.tags_known = []
        self.tags_error = []
        self.tags_unknown = []
        # string reported by client
        self.client_version = None
        self.osversion = None
        self.uname = None
        # for SNMP
        self.oids = {}
        self.snmp_disk_last = None
        self.snmp_disk_oid = []
        self.snmp_columns = []
        self.snmp_community = 'public'
        # last time we read analysis
        self.rules["DISK"] = None
        self.rules["INODE"] = None
        self.rules["PORT"] = []
        self.rules["PROC"] = []
        self.rules["MEMPHYS"] = None
        self.rules["MEMACT"] = None
        self.rules["MEMSWAP"] = None
        self.rules["CPU"] = None
        self.rules["SENSOR"] = None
        self.certs = {}
        self.sslwarn = 30
        self.sslalarm = 10
        self.dialup = False
        self.ping_success = False
        self.pages = ['all', 'nongreen']
        self.dmesg_last_ts = -1
        self.dmesg = {}
        self.xclass = xclass

    # def debug(self, buf):
    #    if self.edebug:
    #        print(buf)

    def add_test(self, ttype, url, port, column, doipv4, doipv6):
        T = None
        for Tt in self.tests:
            if Tt.type == ttype:
                # self.debug("DEBUG: found test %s" % ttype)
                T = Tt
        if T is None:
            # self.debug(f"DEBUG: create test  {ttype} with URL={url}")
            T = xytest(self.name, ttype, url, port, column)
            self.tests.append(T)
        else:
            T.add(url)
        T.doipv4 = doipv4
        T.doipv6 = doipv6

    def gethost(self):
        if self.use_ip:
            return self.hostip
        return self.name

    def dump(self):
        for test in self.tests:
            test.dump()

    def add_rule_proc(self, setting):
        # first verify there is no rule with same pattern
        name = setting.name
        for rule in list(self.rules["PROC"]):
            if rule.name == name:
                self.rules["PROC"].remove(rule)
        self.rules["PROC"].append(setting)

    def add_rule_port(self, setting):
        # first verify there is no rule with same pattern
        for rule in list(self.rules["PORT"]):
            if rule.local == setting.local \
                and rule.state == setting.state \
                and rule.rstate == setting.rstate:
                self.rules["PORT"].remove(rule)
        self.rules["PORT"].append(setting)

class host_selector:
    def __init__(self):
        self.hosts = []
        self.exhosts = []
        self.xclass = []
        self.exclass = []
        self.regex = None
        self.exregex = None
        self.all = False

    def setregex(self, r, exclude=False):
        if r[0] != '%':
            return False
        if exclude:
            self.exregex = r[1:]
        else:
            self.regex = r[1:]
        # TODO compile regex for validating it

    def match(self, H):
        hostname = H.name
        xclass = H.xclass
        if hostname in self.exhosts:
            return False
        if xclass in self.exclass:
            return False
        if self.exregex:
            ret = re.search(self.exregex, hostname)
            # print(f"DEBUG: SELECTOR check {hostname} against {self.exregex} ret={ret}")
            if ret:
                return False
        if self.all:
            return True
        if hostname in self.hosts:
            return True
        if xclass in self.xclass:
            return True
        if self.regex:
            ret = re.search(self.regex, hostname)
            if ret:
                return True
        return False

    def dump(self):
        print(f"DEBUG: H={self.hosts} EX={self.exhosts} ALL={self.all} R={self.regex} EXR={self.exregex}")

class xytest:
    def __init__(self, hostname, ttype, url, port, column):
        self.ts = time.time()
        self.hostname = hostname
        self.next = time.time()
        self.type = ttype
        self.urls = []
        self.urls.append(url)
        self.port = port
        self.column = column
        self.doipv4 = False
        self.doipv6 = False

    def add(self, url):
        self.urls.append(url)

    def dump(self):
        print(f"TEST DUMP: {self.hostname} {self.type} {self.urls}")


class xythonsrv:
    def __init__(self):
        self.RET_OK = 0
        self.RET_ERR = 1
        self.RET_NEW = 2
        self.xy_hosts = {}
        self.xy_hosts_alias = {}
        self.tests = []
        self.xythonmode = 2
        self.uclients = []
        self.clients = []
        self.s = None
        self.us = None
        self.netport = 1984
        self.tlsport = 1985
        self.ipv6 = False
        self.lldebug = False
        self.readonly = False
        self.rules = {}
        self.rules["DISK"] = None
        self.rules["INODE"] = None
        self.rules["PORT"] = []
        self.rules["PROC"] = []
        self.rules["MEMPHYS"] = None
        self.rules["MEMACT"] = None
        self.rules["MEMSWAP"] = None
        self.rules["CPU"] = None
        self.rules["SENSOR"] = None
        self.autoreg = True
        self.celtasks = []
        self.celerytasks = {}
        self.celery_workers = None
        # timestamp for doing actions
        self.ts_page = time.time()
        self.ts_tests = time.time()
        self.ts_check = time.time()
        self.ts_read_configs = time.time()
        self.ts_genrrd = time.time()
        self.ts_xythond = time.time()
        self.time_read_analysis = 0
        self.expires = []
        self.stats = {}
        self.uptime_start = time.time()
        self.etcdir = '/etc/xymon'
        self.xt_logdir = "/var/log/xython/"
        self.wwwdir = None
        self.xy_data = None
        self.xt_data = None
        self.xt_rrd = None
        self.xt_state = None
        self.vars = {}
        self.debugs = []
        self.errors = []
        self.msgn = 0
        # to be compared with mtime of hosts.cfg
        self.time_read_hosts = 0
        self.mtimes_hosts = {}
        # each time read_hosts is called, read_hosts_cnt is ++ abd all hosts found are set to this value
        # so all hosts with a lower value need to be removed
        self.read_hosts_cnt = 0
        self.daemon_name = "xythond"
        self.protocols = {}
        self.time_read_protocols = 0
        self.time_read_graphs = 0
        self.time_read_rrddef = 0
        self.time_read_xserver_cfg = 0
        self.time_read_client_local_cfg = 0
        self.xymonserver_cfg = {}
        self.graphscfg = {}
        self.rrddef = {}
        self.client_local_cfg = {}
        # list rrd to display per column
        self.rrd_column = {}
        self.rrd_column["cpu"] = ['la']
        self.rrd_column["disk"] = ['disk']
        self.rrd_column["inode"] = ['inode']
        self.rrd_column["memory"] = ['memory']
        self.rrd_column["snmp"] = ['snmp']
        self.rrd_column["conn"] = ['connrtt']
        self.rrd_column["sensor"] = ['sensor']
        # timings
        self.RRD_INTERVAL = 5 * 60
        self.RRDWIDTH = 576
        self.RRDHEIGHT = 140
        # at which interval state/client send their status
        # default 5 minute
        self.ST_INTERVAL = 5 * 60
        self.NETTEST_INTERVAL = 2 * 60
        self.XYTHOND_INTERVAL = 2 * 60
        self.GENPAGE_INTERVAL = 30
        # xymon use 512K by default
        self.MAX_MSG_SIZE = 512 * 1024
        self.ghosts = []
        self.quit = 0
        self.pagelist = {}
        self.pagelist['all'] = {}
        self.pagelist['nongreen'] = {}
        self.logger = logging.getLogger('xython')
        self.logger.setLevel(logging.INFO)
        self.loggers = {}
        self.tz = 'Europe/Paris'
        self.tls_cert = None
        self.tls_key = None
        self.colnames = {}
        self.colnames['mdstat'] = 'raid'
        self.inventory_cache = {}

    def stat(self, name, value):
        if name not in self.stats:
            self.stats[name] = {}
            self.stats[name]["cumul"] = 0
            self.stats[name]["count"] = 0
            self.stats[name]["min"] = 10000000
            self.stats[name]["max"] = 0
        self.stats[name]["last"] = value
        self.stats[name]["cumul"] += value
        self.stats[name]["count"] += 1
        if value < self.stats[name]["min"]:
            self.stats[name]["min"] = value
        if value > self.stats[name]["max"]:
            self.stats[name]["max"] = value
        if self.stats[name]["count"] % 100 != 0:
            return

        return
        print("STAT %s count=%d moy=%f min=%f max=%f" % (
            name,
            self.stats[name]["count"],
            self.stats[name]["cumul"] / self.stats[name]["count"],
            self.stats[name]["min"],
            self.stats[name]["max"]))

    def history_update(self, hostname, cname, ts, duration, color, ocolor):
        req = f'INSERT INTO history(hostname, column, ts, duration, color, ocolor)VALUES ("{hostname}", "{cname}", {ts}, {duration}, "{color}", "{ocolor}")'
        self.sqc.execute(req)

    # used only at start, expire is set to let enough time to arrive before purpleing
    def column_set(self, hostname, cname, color, ts, expire, ts_expire):
        color = gcolor(color)
        now = time.time()
        if ts_expire is None:
            ts_expire = now + expire
        req = f'INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color) VALUES ("{hostname}", "{cname}", {ts}, {ts_expire}, "{color}")'
        self.sqc.execute(req)

    def enable_debug(self):
        self.lldebug = True
        self.logger.setLevel(logging.DEBUG)

    def debug(self, buf):
        if self.lldebug:
            print(buf)
        self.logger.debug(buf)

    def debugdev(self, facility, buf):
        if self.lldebug and facility in self.debugs:
            self.logger.debug(buf)
            self.log_create(facility)
            self.loggers[facility].debug(buf)

    def log_create(self, facility):
        if facility not in self.loggers:
            self.loggers[facility] = logging.getLogger(f'xython-{facility}')
            self.loggers[facility].setLevel(logging.DEBUG)
            FileOutputHandler = logging.FileHandler(self.xt_logdir + f'{facility}.log')
            FileOutputHandler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
            self.loggers[facility].addHandler(FileOutputHandler)

    def log(self, facility, buf):
        self.logger.info(buf)
        self.log_create(facility)
        self.loggers[facility].info(buf)

    def error(self, buf):
        print(buf)
        self.log("error", buf)
        elog = {}
        elog["ts"] = time.time()
        elog["msg"] = buf
        self.errors.append(elog)
        self.logger.error(buf)

    def get_last_error(self):
        return self.errors[-1]

    # get configuration values from xython
    def xython_getvar(self, varname):
        try:
            f = open(f"{self.etcdir}/xython.cfg", 'r')
        except FileNotFoundError:
            self.error(f"ERROR: Fail to open {self.etcdir}/xython.cfg: FileNotFound")
            return None
        for line in f:
            line = line.rstrip()
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            sline = line.split("=")
            if len(sline) < 1:
                continue
            if sline[0] == varname:
                found = sline[1]
                # self.debug(f"getvar {varname}={found}")
                return found
        self.debugdev('vars', "DEBUG: did not found %s" % varname)
        return None

    def xython_is_ack(self, hostname, column):
        req = f'SELECT ackend, ackcause FROM columns WHERE hostname="{hostname}" AND column="{column}"'
        self.sqc.execute(req)
        results = self.sqc.fetchall()
        if len(results) == 0:
            return None
        if results[0][0] is None:
            return None
        return results

    # delete all data about a column
    def drop_column(self, hostname, column):
        self.debug(f"DROP COLUMN {hostname} {column}")
        ret = ""
        # delete internal state
        req = f'DELETE FROM columns WHERE hostname = "{hostname}" AND column = "{column}"'
        res = self.sqc.execute(req)
        # verify it is clean
        req = f'SELECT * FROM columns WHERE hostname = "{hostname}" AND column = "{column}"'
        res = self.sqc.execute(req)
        results = self.sqc.fetchall()
        for res in results:
            self.debug(f"DEBUG: DROP REMAIN {res}")
        # drop hist
        dropfile = f"{self.xt_histdir}/{hostname}.{column}"
        if os.path.exists(dropfile):
            self.debug(f"DEBUG: remove {dropfile}")
            os.unlink(dropfile)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropfile}")
        # drop histlogs
        dropfile = f"{self.xt_histlogs}/{hostname}/{column}"
        if os.path.exists(dropfile):
            self.debug(f"DEBUG: remove {dropfile}")
            shutil.rmtree(dropfile)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropfile}")
        # remove xython state
        dropfile = f"{self.xt_state}/{hostname}/{column}"
        if os.path.exists(dropfile):
            self.debug(f"DEBUG: remove {dropfile}")
            os.unlink(dropfile)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropfile}")
        return ret

    def handle_drop(self, buf):
        # DROP HOSTNAME
        # DROP HOSTNAME TEST
        sbuf = buf.rstrip().split(" ")
        if len(sbuf) < 2 or len(sbuf) > 3:
            self.error("ERROR: invalid drop command")
            return False
        column = None
        hostname = sbuf[1]
        if len(sbuf) == 3:
            column = sbuf[2].rstrip()
        H = self.find_host(hostname)
        if H is None:
            self.log(self.daemon_name, f"WARNING: drop unknow hostname {hostname}")
            return False
        self.debug(f"DEBUG: DROP {hostname} {column}")
        if column is not None:
            self.drop_column(hostname, column)
            return True
        # drop all columns
        dropdir = f"{self.xt_histlogs}/{hostname}/"
        try:
            dirFiles = os.listdir(dropdir)
        except:
            self.error(f"ERROR: fail to open {dropdir}")
            return False
        for col in dirFiles:
            self.debug(f"DEBUG: will remove {col}")
            self.drop_column(hostname, col)
        req = f'DELETE FROM columns WHERE hostname = "{hostname}"'
        res = self.sqc.execute(req)
        req = f'SELECT * FROM columns WHERE hostname = "{hostname}"'
        res = self.sqc.execute(req)
        results = self.sqc.fetchall()
        for res in results:
            self.debug(f"DEBUG: DROP REMAIN {res}")
        # drop hostdata
        dropdir = f"{self.xt_hostdata}/{hostname}"
        if os.path.exists(dropdir):
            self.debug(f"DEBUG: remove {dropdir}")
            shutil.rmtree(dropdir)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropdir}")
        # drop histlogs
        dropdir = f"{self.xt_histlogs}/{hostname}/"
        if os.path.exists(dropdir):
            self.debug(f"DEBUG: remove directory {dropdir}")
            shutil.rmtree(dropdir)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropdir}")
        # remove xython state
        dropdir = f"{self.xt_state}/{hostname}/"
        if os.path.exists(dropdir):
            self.debug(f"DEBUG: remove directory {dropdir}")
            shutil.rmtree(dropdir)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropdir}")
        # drop hist
        dropfile = f"{self.xt_histdir}/{hostname}"
        if os.path.exists(dropfile):
            self.debug(f"DEBUG: remove {dropfile}")
            os.unlink(dropfile)
        else:
            self.debug(f"DEBUG: Cannot remove non-existent {dropfile}")

        # reload hosts.cfg
        self.read_hosts()
        return True

    def parse_collector(self, buf):
        lines = buf.split("\n")
        line = lines[0].rstrip()
        if line[:7] != 'client ':
            if len(lines) < 2:
                return None
            if lines[0].rstrip() != '[collector:]':
                return None
            line = lines[1].rstrip()
        if line[:7] != 'client ':
            return None
        # parse hostname.ostype hostclass
        tokens = line.split(" ")
        if len(tokens) > 3 or len(tokens) < 2:
            return None
        if len(tokens) == 3:
            hostclass = tokens[2]
        else:
            hostclass = None
        hist_os = tokens[1]
        tokens = hist_os.split(".")
        if len(tokens) < 2:
            return None
        ostype = tokens.pop(-1)
        hostname = ".".join(tokens)
        hostname = hostname.rstrip()
        # check if hostname is an alias
        H = self.find_host(hostname)
        if H and H.name != hostname:
            hostname = H.name
        if not H:
            ret = self.ghost(hostname)
            if ret != self.RET_NEW:
                return None
        return [hostname, ostype, hostclass]

    def send_client_local(self, buf):
        ret = self.parse_collector(buf)
        if ret is None:
            return None
        # now seek hostname in client local
        if ret[0] in self.client_local_cfg:
            return self.client_local_cfg[ret[0]]
        # check hostclass
        if ret[2] in self.client_local_cfg:
            return self.client_local_cfg[ret[2]]
        # check ostype
        if ret[1] in self.client_local_cfg:
            return self.client_local_cfg[ret[1]]
        return None

    def load_client_local_cfg(self):
        pclientlocalcfg = f"{self.etcdir}/client-local.cfg"
        try:
            mtime = os.path.getmtime(pclientlocalcfg)
        except FileNotFoundError:
            self.error(f"ERROR: fail to get mtime of {pclientlocalcfg}")
            return self.RET_ERR
        # self.debug(f"DEBUG: read {pclientlocalcfg} mtime={mtime}")
        if self.time_read_client_local_cfg < mtime:
            self.time_read_client_local_cfg = mtime
        else:
            return self.RET_OK
        # self.debug(f"DEBUG: read {pclientlocalcfg}")
        try:
            clientlocalcfg = open(pclientlocalcfg, 'r')
        except:
            self.error(f"ERROR: cannot open {pclientlocalcfg}")
            return self.RET_ERR
        lines = clientlocalcfg.readlines()
        section = None
        for line in lines:
            line = line.rstrip()
            line = line.lstrip()
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            if line[0] == '[':
                line = line[1:]
                tokens = line.split(']')
                if len(tokens) == 0:
                    continue
                section = tokens[0]
                if section in self.client_local_cfg:
                    self.error(f"ERROR: section {section} present twice in {pclientlocalcfg}")
                else:
                    self.client_local_cfg[section] = []
                continue
            self.client_local_cfg[section].append(line)
        return self.RET_OK

    def load_xymonserver_cfg(self):
        pxserver = f"{self.etcdir}/xymonserver.cfg"
        try:
            mtime = os.path.getmtime(pxserver)
        except FileNotFoundError:
            self.error(f"ERROR: fail to get mtime of {pxserver}")
            return self.RET_ERR
        if self.time_read_xserver_cfg < mtime:
            self.time_read_xserver_cfg = mtime
        else:
            return self.RET_OK
        try:
            xserver = open(pxserver, 'r')
        except:
            self.error(f"ERROR: cannot open {pxserver}")
            return self.RET_ERR
        lines = xserver.readlines()
        for line in lines:
            line = line.rstrip()
            line = line.lstrip()
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            if '=' not in line:
                self.debug(f"DEBUG: invalid line {line}")
                continue
            tok = line.split('=')
            if len(tok) < 2:
                self.error(f"ERROR: invalid line {line}")
                continue
            var = tok.pop(0)
            raw = "=".join(tok)
            if len(raw) == 0:
                self.error(f"ERROR: invalid line {line}")
                continue
            value = ""
            if raw[0] != '"':
                i = 0
                while i < len(raw) and raw[i] != ' ':
                    # grab until space
                    value += raw[i]
                    i += 1
            else:
                i = 1
                while i < len(raw):
                    if raw[i] == '\\':
                        i += 1
                    if raw[i] == '"':
                        if raw[i - 1] != '\\':
                            break
                    value += raw[i]
                    i += 1
            self.xymonserver_cfg[var] = value
        ret = 1
        while ret > 0:
            ret = self.xymonserver_cfg_resolve()
            self.debug(f"RESOLVE RET={ret}")
        return self.RET_OK

    # replace variables
    # return number of replaced variable
    def xymonserver_cfg_resolve(self):
        c = 0
        for name in self.xymonserver_cfg:
            value = self.xymonserver_cfg[name]
            dvars = re.findall(r"\$[A-Z]+", value)
            self.debugdev('vars', f"DEBUG: {name} = {value}")
            for var in dvars:
                vname = var[1:]
                if vname in self.xymonserver_cfg:
                    c += 1
                    v = self.xymonserver_cfg[vname]
                    self.xymonserver_cfg[name] = self.xymonserver_cfg[name].replace(var, v)
                else:
                    self.error(f"WARNING: xymonserver.cfg: {vname} not found")
        return c

    # get variables from /etc/xymon
    def xymon_getvar(self, varname):
        if varname in self.vars:
            return self.vars[varname]
        if varname in self.xymonserver_cfg:
            return self.xymonserver_cfg[varname]
        self.debugdev('vars', "DEBUG: did not found %s" % varname)
        return ""

    def html_history(self, now, history_extra):
        hlist = []
        self.sqc.execute(f"SELECT * FROM history WHERE ts > {now} - 240 *60 {history_extra} ORDER BY ts DESC LIMIT 100")
        results = self.sqc.fetchall()
        hcount = len(results)
        if hcount > 0:
            lastevent = results[hcount - 1]
            minutes = (now - lastevent[2]) // 60 + 1
        else:
            minutes = 0
        hlist.append('<center>')
        hlist.append('<TABLE SUMMARY="$EVENTSTITLE" BORDER=0>\n<TR BGCOLOR="#333333">')
        # TODO minutes
        hlist.append(f'<TD ALIGN=CENTER COLSPAN=6><FONT SIZE=-1 COLOR="#33ebf4">{hcount}&nbsp;events&nbsp;received&nbsp;in&nbsp;the&nbsp;past&nbsp;{minutes}&nbsp;minutes</FONT></TD></TR>\n')
        for change in results:
            hhostname = change[0]
            hcol = change[1]
            hts = change[2]
            hduration = change[3]
            hcolor = change[4]
            hocolor = change[5]
            hlist.append('<TR BGCOLOR=#000000>')
            hlist.append('<TD ALIGN=CENTER>%s</TD>' % xytime(hts))
            hlist.append('<TD ALIGN=CENTER BGCOLOR=%s><FONT COLOR=black>%s</FONT></TD>' % (hcolor, hhostname))
            hlist.append('<TD ALIGN=LEFT>%s</TD>' % hcol)
            hlist.append(f'<TD><A HREF="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hhostname}&amp;SERVICE={hcol}&amp;TIMEBUF={xytime_(hts - hduration)}">')
            hlist.append(f'<IMG SRC="$XYMONSERVERWWWURL/gifs/{gif(hocolor, hts)}"  HEIGHT="16" WIDTH="16" BORDER=0 ALT="{hocolor}" TITLE="{hocolor}"></A>')
            hlist.append('<IMG SRC="$XYMONSERVERWWWURL/gifs/arrow.gif" BORDER=0 ALT="From -&gt; To">')
            hlist.append(f'<TD><A HREF="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hhostname}&amp;SERVICE={hcol}&amp;TIMEBUF={xytime_(hts)}">')
            hlist.append(f'<IMG SRC="$XYMONSERVERWWWURL/gifs/{gif(hcolor, hts)}"  HEIGHT="16" WIDTH="16" BORDER=0 ALT="{hcolor}" TITLE="{hcolor}"></A>')
            hlist.append('</TR>')
        hlist.append('</center>')
        return hlist

    def html_header(self, header):
        # self.debug(f"DEBUG: read {self.webdir}/{header}")
        fname = f"{self.webdir}/{header}"
        try:
            fh = open(fname, "r")
            html = fh.readlines()
            fh.close()
        except FileNotFoundError as e:
            self.error(f"ERROR: fail to open {fname}")
            return [f"<h1>ERROR: Fail to open {fname} {str(e)}</h1>"]
        return html

    def html_footer(self, footer):
        fname = f"{self.webdir}/{footer}"
        try:
            fh = open(fname, "r")
            html = fh.readlines()
            fh.close()
        except FileNotFoundError as e:
            self.error(f"ERROR: fail to open {fname}")
            return [f"<h1>ERROR: Fail to open {fname} {str(e)}</h1>"]
        return html

    # replace all variables in HTML
    # this means also adding xymonmenu
    def html_finalize(self, color, hlist, pagename):
        ts_start = time.time()
        html = '\n'.join(hlist)
        fh = open(self.etcdir + "/xymonmenu.cfg")
        body_header = fh.read()
        fh.close()
        html = re.sub("&XYMONBODYHEADER", body_header, html)
        html = re.sub("&XYMONBODYFOOTER", "", html)
        html = re.sub("&XYMONDREL", f'{version("xython")}', html)
        html = re.sub("&XYMWEBREFRESH", "60", html)
        html = re.sub("&XYMWEBBACKGROUND", color, html)
        html = re.sub("&XYMWEBDATE", xytime(time.time()), html)
        html = re.sub("&HTMLCONTENTTYPE", self.xymon_getvar("HTMLCONTENTTYPE"), html)
        now = time.time()
        html = re.sub("&EVENTLASTYEARBEGIN", event_lastyear(now), html)
        html = re.sub("&EVENTLASTMONTHBEGIN", event_lastmonth(now), html)
        html = re.sub("&EVENTLASTWEEKBEGIN", event_lastweek(now), html)
        html = re.sub("&EVENTCURRYEARBEGIN", event_thisyear(now), html)
        html = re.sub("&EVENTCURRMONTHBEGIN", event_thismonth(now), html)
        html = re.sub("&EVENTCURRWEEKBEGIN", event_thisweek(now), html)
        html = re.sub("&EVENTYESTERDAY", event_yesterday(now), html)
        html = re.sub("&EVENTTODAY", event_today(now), html)
        html = re.sub("&EVENTNOW", xyevent(time.time()), html)
        if pagename == 'topchanges':
            html = re.sub("&SCRIPT_NAME", "topchanges.py", html)
        # find remaining variables
        ireplace = 0
        matcher1 = re.compile(r"\&XY[A-Z][A-Z]*")
        matcher2 = re.compile(r"\$XY[A-Z][A-Z]*")
        while ireplace < 2:
            toreplace = re.findall(matcher1, html)
            toreplaceu = {}
            for x in toreplace:
                toreplaceu[x] = ""
            for xvar in toreplaceu:
                xvarbase = xvar.replace("&", "")
                html = re.sub(xvar, self.xymon_getvar(xvarbase), html)
            toreplace = re.findall(matcher2, html)
            toreplaceu = {}
            for x in toreplace:
                toreplaceu[x] = ""
            for xvar in toreplaceu:
                xvarbase = xvar.replace("$", "")
                html = re.sub(r"\$%s" % xvarbase, self.xymon_getvar(xvarbase), html)
            ireplace += 1
        self.stat('HTML_FINALIZE', time.time() - ts_start)
        return html

    def html_page(self, pagename):
        now = time.time()
        history_extra = ""
        color = 'blue'
        if pagename == 'acknowledgements':
            header = 'acknowledge_header'
            footer = 'acknowledge_footer'
        elif pagename == 'topchanges':
            header = 'topchanges_header'
            footer = 'topchanges_footer'
        elif pagename == 'topchanges_answer':
            header = 'topchanges_header'
            footer = 'topchanges_footer'
        else:
            header = 'stdnormal_header'
            footer = 'stdnormal_footer'
        hlist = self.html_header(header)
        if pagename == 'acknowledgements':
            req = "SELECT hostname, column, ackend, ackcause FROM columns WHERE ackend != 0"
            self.sqc.execute(req)
            results = self.sqc.fetchall()
            for res in results:
                print(res)
                hostname = res[0]
                column = res[1]
                ackend = res[2]
                ackcause = res[3]
                hlist.append(f"{hostname} {column} {ackcause} {ackend} {xytime(ackend)}\n<br>")
        elif pagename == 'expires':
            req = "SELECT hostname, column, expire FROM columns ORDER BY expire ASC"
            self.sqc.execute(req)
            results = self.sqc.fetchall()
            for res in results:
                hostname = res[0]
                column = res[1]
                expire = res[2]
                hlist.append(f"{hostname} {column} {expire} {xytime(expire)}\n<br>")
        elif pagename == 'topchanges':
            fname = f"{self.webdir}/topchanges_form"
            try:
                fh = open(fname, "r")
                hlist += fh.readlines()
                fh.close()
            except FileNotFoundError as e:
                hlist.append(f"<h1>ERROR: Fail to open {fname} {str(e)}</h1>")
                self.error(f"ERROR: fail to open {fname}")
        else:
            ret = self.html_hostlist(pagename, None)
            hlist += ret["html"]
            color = ret["color"]
            if 'group' in self.pagelist[pagename]:
                for group in self.pagelist[pagename]['group']:
                    ret = self.html_hostlist(pagename, group)
                    hlist += ret["html"]
                    color = setcolor(ret["color"], color)
            if pagename in ['all', 'nongreen']:
                hlist += self.html_history(now, history_extra)
        hlist += self.html_footer(footer)
        html = self.html_finalize(color, hlist, pagename)
        return html

    def html_hostlist(self, pagename, group):
        self.debugdev("page", f"DEBUG: html_hostlist for {pagename} group={group}")
        now = time.time()
        hlist = []
        color = 'green'
        # dump hosts
        hlist.append("<center>\n")
        hlist.append('<A NAME=begindata>&nbsp;</A>\n')
        hlist.append('<A NAME="hosts-blk">&nbsp;</A>\n')
        hlist.append('<A NAME=hosts-blk-1>&nbsp;</A>\n')

        if group is not None:
            grouptitle = group
            if 'title' in self.pagelist[pagename]['group'][group]:
                grouptitle = self.pagelist[pagename]['group'][group]['title']
            hlist.append(f'<CENTER><TABLE SUMMARY="{group} Group Block" BORDER=0 CELLPADDING=2>\n')
            hlist.append(f'<TR><TD VALIGN=MIDDLE ROWSPAN=2><CENTER><FONT COLOR="#FFFFF0" SIZE="+1">{grouptitle}</FONT></CENTER></TD>')
        else:
            hlist.append('<CENTER><TABLE SUMMARY=" Group Block" BORDER=0 CELLPADDING=2>\n')
            hlist.append('<TR><TD VALIGN=MIDDLE ROWSPAN=2><CENTER><FONT COLOR="#FFFFF0" SIZE="+1"></FONT></CENTER></TD>')
        if pagename == 'nongreen':
            self.sqc.execute("SELECT DISTINCT column FROM columns WHERE color != 'green' AND color != 'blue' AND color != 'clear' AND hostname IN (SELECT DISTINCT hostname FROM pages WHERE pagename == 'nongreen') ORDER BY column")
        else:
            self.sqc.execute(f'SELECT DISTINCT column FROM columns WHERE hostname IN (SELECT DISTINCT hostname FROM pages WHERE pagename == "{pagename}" AND groupname == "{group}") ORDER BY column')
        results = self.sqc.fetchall()
        cols = []
        for col in results:
            colname = col[0]
            if group is not None:
                if 'group-only' in self.pagelist[pagename]['group'][group]:
                    if colname not in self.pagelist[pagename]['group'][group]['group-only']:
                        continue
                if 'group-except' in self.pagelist[pagename]['group'][group]:
                    if colname in self.pagelist[pagename]['group'][group]['group-except']:
                        continue
            cols.append(colname)
            hlist.append(f'<TD ALIGN=CENTER VALIGN=BOTTOM WIDTH=45>\n<A HREF="$XYMONSERVERCGIURL/columndoc.sh?{colname}"><FONT COLOR="#87a9e5" SIZE="-1"><B>{colname}</B></FONT></A> </TD>\n')
        hlist.append('</TR><TR><TD COLSPAN={len(results)}><HR WIDTH="100%%"></TD></TR>\n')

        if pagename == 'nongreen':
            self.sqc.execute('SELECT hostname,column,ts,color FROM columns WHERE hostname IN (SELECT DISTINCT hostname FROM columns WHERE color != "green" and color != "blue" and color != "clear") AND column IN (SELECT DISTINCT column FROM columns where color != "green" AND color != "blue" AND color != "clear") AND hostname IN (SELECT DISTINCT hostname FROM pages WHERE pagename == "nongreen") ORDER by hostname, column')
        else:
            self.sqc.execute(f'SELECT hostname,column,ts,color FROM columns WHERE hostname IN (SELECT DISTINCT hostname FROM pages WHERE pagename == "{pagename}" AND groupname == "{group}") ORDER BY hostname,column')
        results = self.sqc.fetchall()
        chost = None
        ci = 0
        for result in results:
            hostname = result[0]
            if hostname != chost:
                # finish feeding with '-'
                while ci > 0 and ci < len(cols):
                    ci += 1
                    hlist.append('<TD ALIGN=CENTER>-</TD>\n')
                if chost is not None:
                    hlist.append('</TR>\n')
                chost = hostname
                ci = 0
                hlist.append('<TR class=line>\n')
                hlist.append(f'<TD NOWRAP ALIGN=LEFT><A NAME="{hostname}">&nbsp;</A>\n')
                hlist.append(f'<A HREF="/xython/xython.html" ><FONT SIZE="+1" COLOR="#FFFFCC" FACE="Tahoma, Arial, Helvetica">{hostname}</FONT></A>')
            Cname = result[1]
            if Cname not in cols:
                # print(f"IGNORE {Cname} not in {cols}")
                continue
            lts = result[2]
            lcolor = result[3]
            if lcolor in ["red", "yellow"]:
                color = setcolor(lcolor, color)
            dhm = xydhm(lts, now)
            acki = self.xython_is_ack(hostname, Cname)
            if acki is None or lcolor == 'green':
                isack = False
            else:
                isack = True
            while Cname != cols[ci]:
                hlist.append('<TD ALIGN=CENTER>-</TD>\n')
                ci += 1
                if ci >= len(cols):
                    self.error(f"BUG: ci={ci} cols={cols} ")
            hlist.append('<TD ALIGN=CENTER>')
            hlist.append(f'<A HREF="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hostname}&amp;SERVICE={Cname}">')
            hlist.append(f'<IMG SRC="/xython/gifs/{gif(lcolor, lts, isack)}" ALT="{Cname}:{lcolor}:{dhm}" TITLE="{Cname}:{lcolor}:{dhm}" HEIGHT="16" WIDTH="16" BORDER=0></A></TD>')
            ci += 1
        # finish feeding with '-'
        while ci > 0 and ci < len(cols):
            ci += 1
            hlist.append('<TD ALIGN=CENTER>-</TD>\n')

        hlist.append('</TR>\n</TABLE></CENTER><BR>')

        # end nongreen
        #if pagename in ['all', 'nongreen']:
            # TODO move this
        #    hlist += self.html_history(now, "")
        ret = {}
        ret["color"] = color
        ret["html"] = hlist
        return ret

    def write_html(self, pagename, html):
        fhtml = open(self.wwwdir + f'/{pagename}.html', 'w')
        fhtml.write(html)
        fhtml.close()
        # TODO find a better solution
        os.chmod(self.wwwdir + f"/{pagename}.html", 0o644)

    def gen_htmls(self):
        for pagename in self.pagelist:
            self.debugdev("page", f"DEBUG: will generate page {pagename}")
            #html = self.gen_html(pagename, None, None, None)
            html = self.html_page(pagename)
            if pagename == 'nongreen':
                self.write_html(pagename, html)
                continue
            if pagename == 'all':
                self.write_html('xython', html)
                if self.xythonmode > 0:
                    self.write_html('xymon', html)
                continue
            if pagename != 'svcstatus':
                reldir = os.path.dirname(pagename)
                fdir = f'{self.wwwdir}/{reldir}'
                if not os.path.exists(fdir):
                    self.debugdev("page", f'CREATE {fdir}')
                    os.mkdir(fdir)
                    os.chmod(fdir, 0o755)
                self.write_html(pagename, html)

    # TODO template jinja ?
    def gen_html(self, pagename, hostname, column, ts):
        now = time.time()
        color = 'green'
        hlist = self.html_header('stdnormal_header')

        if pagename != 'svcstatus':
            ts = time.time()
            ret = self.html_hostlist(pagename, None)
            hlist += ret["html"]
            color = ret["color"]
            if 'group' in self.pagelist[pagename]:
                for group in self.pagelist[pagename]['group']:
                    ret = self.html_hostlist(pagename, group)
                    hlist += ret["html"]
                    color = setcolor(ret["color"], color)
            self.stat("HTML_hostlist", time.time() - ts)

        history_extra = ""
        if pagename == 'svcstatus':
            rdata = self.get_histlogs(hostname, column, ts)
            if rdata is None:
                html = "HIST not found"
                return html
            color = rdata["first"].split(' ')[0]
            if not is_valid_color(color):
                html = 'Invalid DATA'
                return html
            hlist.append('<CENTER><TABLE ALIGN=CENTER BORDER=0 SUMMARY="Detail Status">')
            # TODO replace with first line of status (without color)
            hlist.append('<TR><TD ALIGN=LEFT><H3>%s</H3>' % rdata["first"])
            hlist.append('<PRE>')
            data = ''.join(rdata["data"])
            data.replace("\n", '<br>\n')
            # data = re.sub("\n", '<br>\n', data)
            for gifc in COLORS:
                data = re.sub("&%s" % gifc, '<IMG SRC="$XYMONSERVERWWWURL/gifs/%s.gif">' % gifc, data)
            hlist.append(data)
            hlist.append('</PRE>\n</TD></TR></TABLE>')
            hlist.append('<br><br>\n')
            hlist.append('<table align="center" border=0 summary="Status report info">')
            hlist.append(f'<tr><td align="center"><font COLOR="#87a9e5" SIZE="-1">Status unchanged in {xydhm(ts, now)}<br>')
            hlist.append('Status %s<br>' % rdata["sender"])
            if self.xythonmode > 0:
                hlist.append('<a href="$XYMONSERVERCGIURL/xythoncgi.py?CLIENT={hostname}">Client data</a> available<br>')
            else:
                hlist.append('<a href="$XYMONSERVERCGIURL/svcstatus.sh?CLIENT={hostname}">Client data</a> available<br>')
            hlist.append('</font></td></tr>\n</table>\n</CENTER>\n<BR><BR>\n')
            history_extra = f'AND hostname="{hostname}" AND column="{column}"'

            self.sqc.execute(f'SELECT ackend, ackcause FROM columns WHERE hostname == "{hostname}" and column == "{column}"')
            ackinfos = self.sqc.fetchall()
            if len(ackinfos) == 1:
                ackinfo = ackinfos[0]
                ackend = ackinfo[0]
                if ackend is not None:
                    ackmsg = ackinfo[1]
                    hlist.append(f'<CENTER>Current acknowledgement: {ackmsg}<br>Next update at: {xytime(int(ackend))}</CENTER>\n')
            else:
                print(f"ackinfo is len={len(ackinfo)}")
            # TODO acknowledge is only for non-history and non-green
            # if color != 'green':
            hlist.append('<CENTER>\n<form action="$XYMONSERVERCGIURL/xythoncgi.py" method="post">\n')
            hlist.append('<input type="text" placeholder="61" SIZE=6 name="duration" required>\n')
            hlist.append('<input type="text" placeholder="ack message" name="cause" required>\n')
            hlist.append(f'<input type="hidden" name="hostname" value="{hostname}">\n')
            hlist.append(f'<input type="hidden" name="service" value="{column}">\n')
            hlist.append('<input type="hidden" name="action" value="ack">\n')
            # hlist.append(f'<input type="hidden" name="returnurl" value="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hostname}&amp;SERVICE={column}">\n'
            hlist.append('<button type="submit">Send ack</button></form>\n')
            hlist.append('</CENTER>\n')

            hlist.append('<CENTER>\n<form action="$XYMONSERVERCGIURL/xythoncgi.py" method="post">\n')
            hlist.append('<input type="text" placeholder="61" SIZE=6 name="duration" required>\n')
            hlist.append('<input type="text" placeholder="disable message" name="cause" required>\n')
            hlist.append(f'<input type="hidden" name="hostname" value="{hostname}">\n')
            hlist.append(f'<input type="text" name="dservice" value="{column}">\n')
            hlist.append(f'<input type="hidden" name="service" value="{column}">\n')
            hlist.append('<input type="hidden" name="action" value="disable">\n')
            # hlist.append(f'<input type="hidden" name="returnurl" value="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hostname}&amp;SERVICE={column}">\n'
            hlist.append('<button type="submit">Send blue</button></form>\n')
            hlist.append('</CENTER>\n')

            # hlist.append(f"Status valid until {xytime()}"

            if has_rrdtool:
                if column in self.rrd_column:
                    for rrdname in self.rrd_column[column]:
                        # hlist.append(f'<CENTER><img src="/xython/{hostname}/{rrdname}.png"></CENTER>'
                        hlist.append(f'<CENTER><img src="$XYMONSERVERCGIURL/showgraph.py?hostname={hostname}&service={rrdname}"></CENTER>')

        # history
        if pagename in ["svcstatus", "all", "nongreen"]:
            hlist += self.html_history(now, history_extra)

        hlist += self.html_footer('stdnormal_footer')

        html = self.html_finalize(color, hlist, pagename)

        return html

    def dump(self, hostname):
        print("======= DUMP HOST %s" % hostname)
        H = self.find_host(hostname)
        if H is None:
            return
        req = f'SELECT * FROM columns WHERE hostname == "{hostname}"'
        self.sqc.execute(req)
        results = self.sqc.fetchall()
        for sqr in results:
            print(f'{sqr[1]} {sqr[4]} TS={sqr[2]}')
        for T in H.tests:
            for url in T.urls:
                print("\tTEST: %s %s" % (T.type, url))
        print(H.rules)

    def read_snmp_hosts(self, hostname):
        H = self.find_host(hostname)
        fname = f"{self.etcdir}/snmp.d/{hostname}"
        try:
            f = open(fname)
        except FileNotFoundError as e:
            self.error(f"Fail to open {fname} {str(e)}")
            return False
        except PermissionError as e:
            self.error(f"Fail to open {fname} {str(e)}")
            return False
        for line in f:
            line = line.rstrip()
            line = re.sub(r"\s+", " ", line)
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            self.debug(f"\tDEBUG: read {line}")
            t = line.split(";")
            if len(t) < 5:
                self.error(f"ERROR: invalid SNMP custom graph line {line}, not enough tokens")
                # TODO error
                continue
            goid = {}
            goid["oid"] = t[2]
            goid["dsname"] = t[3]
            goid["dsspec"] = t[4]
            rrd = t[0]
            obj = t[1]
            if rrd not in H.oids:
                H.oids[rrd] = {}
            if obj not in H.oids[rrd]:
                H.oids[rrd][obj] = []
            H.oids[rrd][obj].append(goid)
            self.rrd_column[rrd] = [rrd]

    def hosts_check_tags(self):
        for hostname in self.xy_hosts:
            H = self.xy_hosts[hostname]
            if H.tags_read:
                continue
            need_conn = True
            if H.tags is None:
                self.error(f"ERROR: with {H.name} no tags")
                continue
            for tag in H.tags:
                if len(tag) == 0:
                    continue
                self.debug(f"DEBUG: {H.name} {tag}")
                if tag == '#':
                    continue
                if tag[0] == '#':
                    tag = tag[1:]
                if tag[0:6] == 'testip':
                    H.use_ip = True
                    H.tags_known.append(tag)
                    continue
                if tag[0:6] == 'noconn':
                    need_conn = False
                    H.tags_known.append(tag)
                    continue
                if tag[0:10] == 'nonongreen':
                    H.pages.remove('nongreen')
                    H.tags_known.append(tag)
                    continue
                if tag[0:6] == 'nodisp':
                    H.pages.remove('nongreen')
                    H.pages.remove('all')
                    H.tags_known.append(tag)
                    continue
                tokens = tag.split(':')
                test = tokens[0]
                if test in self.protocols:
                    H.add_test(test, tag, None, test, True, False)
                    H.tags_known.append(tag)
                    H.dump()
                    continue
                if tag == 'dialup':
                    H.dialup = True
                    H.tags_known.append(tag)
                    continue
                if tag[0:6] == 'alias=':
                    atok = tag.split("=")
                    if len(atok) != 2:
                        H.tags_error.append(tag)
                        continue
                    aliases = atok[1].split(',')
                    for alias in aliases:
                        HT = self.find_host(alias)
                        if HT:
                            self.error("ERROR: {alias} already used")
                            continue
                        self.add_host_alias(H, alias)
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'fail':
                    H.add_test("fail", tag, None, "fail", True, False)
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'conn':
                    # TODO name of column via =column
                    tokens = tag.split(':')
                    doipv4 = False
                    doipv6 = False
                    for tok in tokens:
                        if tok == 'conn':
                            continue
                        if tok == 'ipv4':
                            doipv4 = True
                            continue
                        if tok == 'ipv6':
                            doipv6 = True
                            continue
                        self.error(f"ERROR: unknow tag option {tok} for conn")
                    H.add_test("conn", tag, None, "conn", doipv4, doipv6)
                    need_conn = False
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'cont':
                    # TODO column name
                    self.debug("\tDEBUG: HTTP cont tests %s" % tag)
                    tokens = tag.split(';')
                    if len(tokens) != 3:
                        self.error(f"ERROR: cont: INVALID {tag}")
                        continue
                    url = f"{tokens[1]};cont={tokens[2]}"
                    H.add_test("http", url, None, "http", True, False)
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'http':
                    url = tag
                    if tag[0:10] == 'httpstatus':
                        # TODO column name
                        tokens = tag.split(';')
                        if len(tokens) != 4:
                            self.error(f"ERROR: httpstatus: INVALID {tag}")
                            continue
                        url = f"{tokens[1]};httpcode={tokens[2]};badhttpcode={tokens[3]};noredirect"
                    self.debug("\tDEBUG: HTTP tests %s" % tag)
                    H.add_test("http", url, None, "http", True, False)
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'snmp':
                    snmp_tags = tag.split(':')
                    snmp_tags.pop(0)
                    for stag in snmp_tags:
                        self.debug(f"DEBUG: check SNMP TAG {stag}")
                        if stag in ['memory', 'disk']:
                            self.debug(f"DEBUG: SNMP add column {stag} to {H.snmp_columns}")
                            H.snmp_columns.append(stag)
                            continue
                        if stag[0:10] == 'community=':
                            H.snmp_community = stag.split('=')[1]
                            continue
                        self.error(f"ERROR: unknow SNMP tag {stag}")
                    self.debug(f"DEBUG: SNMP COLUMNS = {H.snmp_columns}")
                    self.read_snmp_hosts(H.name)
                    H.add_test("snmp", None, None, "snmp", True, False)
                    H.tags_known.append(tag)
                    continue
                if tag[0:7] == 'tssh://':
                    H.tags_known.append(tag)
                    H.add_test("tssh", tag, None, "tssh", True, False)
                    continue
                if tag[0:8] == 'ssldays=':
                    tokens = tag[8:].split(':')
                    if len(tokens) != 2:
                        H.tags_error.append(tag)
                        continue
                    if not tokens[0].isnumeric():
                        H.tags_error.append(tag)
                        continue
                    if not tokens[1].isnumeric():
                        H.tags_error.append(tag)
                        continue
                    H.sslwarn = int(tokens[0])
                    H.sslalarm = int(tokens[1])
                    continue
                self.log(self.daemon_name, f"WARNING: unknow tag={tag} for {H.name}")
                H.tags_unknown.append(tag)
            # end tag
            # self.host_page_clean(H.name)
            for page in H.pages:
                self.host_add_to_page(page, H.name, None)
            if need_conn:
                H.add_test("conn", "conn", None, "conn", True, False)
            self.gen_column_info(H.name)

# read hosts.cfg
# return RET_OK if nothing new was read
# return RET_ERR on error
# return RET_NEW if hosts.cfg was read
    def read_hosts(self):
        try:
            mtime = os.path.getmtime(self.etcdir + "/hosts.cfg")
        except FileNotFoundError as e:
            self.error(f"ERROR: cannot get mtime of hosts.cfg {str(e)}")
            return self.RET_ERR
        except PermissionError as e:
            self.error(f"ERROR: cannot get mtime of hosts.cfg {str(e)}")
            return self.RET_ERR
        # Watch snmp.d
        snmpd_path = self.etcdir + "/snmp.d"
        if os.path.exists(snmpd_path) and snmpd_path not in self.mtimes_hosts:
            self.mtimes_hosts[snmpd_path] = {}
            self.mtimes_hosts[snmpd_path]["mtime"] = 0
            self.mtimes_hosts[snmpd_path]["optional"] = True
        # self.debug(f"DEBUG: compare mtime={mtime} and time_read_hosts={self.time_read_hosts}")
        need_reload = False
        if self.time_read_hosts < mtime:
            self.time_read_hosts = mtime
            need_reload = True
        for fpath in list(self.mtimes_hosts):
            old_mtime = self.mtimes_hosts[fpath]["mtime"]
            self.debug(f"DEBUG: get mtime of {fpath}")
            try:
                cmtime = os.path.getmtime(fpath)
            except FileNotFoundError:
                # file could have be removed
                need_reload = True
                self.debug(f"DEBUG: {fpath} not found")
                del self.mtimes_hosts[fpath]
                continue
            except PermissionError as e:
                self.error(f"ERROR: fail to mtime {fpath} {str(e)}")
                return self.RET_ERR
            self.debug(f"DEBUG: check mtime of {fpath} old={old_mtime} new={cmtime} {old_mtime < cmtime}")
            if cmtime > old_mtime:
                need_reload = True
                self.mtimes_hosts[fpath]["mtime"] = cmtime
        if not need_reload:
            return self.RET_OK
        self.debug(f"DEBUG: read_hosts in {self.etcdir}")
        self.read_hosts_cnt += 1
        # TODO prevent inifine loop (like having directory hosts.d in hosts.d/file)
        return self.read_hosts_file(self.etcdir + "/hosts.cfg")

    def create_host(self, host_name, host_ip, tags):
        # if host already exists, remove it
        host_tags = None
        H = self.find_host(host_name)
        if H is not None:
            if H.rhcnt == self.read_hosts_cnt:
                self.debug(f'DEBUG: duplicate host {H.name}')
                return self.RET_OK
            # old host
            host_tags = H.tags
            self.remove_host(H)
            self.host_page_clean(H.name)
        H = xy_host(host_name)
        H.rhcnt = self.read_hosts_cnt
        H.hostip = host_ip
        if host_tags != tags:
            self.debugdev('loading', f"host {H.name} have some changes from {host_tags} to {tags}")
        else:
            self.debugdev('loading', f"host {H.name} with no changes")
        H.tags = tags
        self.add_host(H)
        return self.RET_OK

    def read_hosts_file(self, fpath):
        # on error it force to reload next time
        self.mtimes_hosts[fpath] = {}
        self.mtimes_hosts[fpath]["mtime"] = 0
        try:
            fhosts = open(fpath, 'r')
        except FileNotFoundError as e:
            self.error(f"ERROR: Cannot open {fpath} {str(e)}")
            return self.RET_ERR
        except PermissionError as e:
            self.error(f"ERROR: Cannot open {fpath} {str(e)}")
            return self.RET_ERR
        if fpath not in self.mtimes_hosts:
            self.mtimes_hosts[fpath] = {}
        try:
            self.mtimes_hosts[fpath]["mtime"] = os.path.getmtime(fpath)
        except FileNotFoundError as e:
            self.error(f"ERROR: Cannot open {fpath} {str(e)}")
            return self.RET_ERR
        self.page_init()
        self.debugdev('loading', f"DEBUG: HOSTS: read {fpath}")
        dhosts = fhosts.read()
        dhosts = dhosts.replace('\\\n', '')
        current_parent = 'all'
        current_page = 'all'
        current_group = 'None'
        for line in dhosts.split('\n'):
            line = line.rstrip()
            line = re.sub(r"\s+", " ", line)
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            sline = line.split(" ")
            if len(sline) < 2:
                self.error(f"ERROR: hosts line is too short {line}")
                continue
            keyword = sline.pop(0)
            if keyword == 'page':
                current_page = sline.pop(0)
                current_parent = current_page
                ret = self.page_add(current_page)
                if ret != self.RET_NEW:
                    return ret
                if len(sline) > 0:
                    self.pagelist[current_parent]['title'] = ' '.join(sline)
                continue

            if keyword == 'subpage':
                current_page = current_parent + '/' + sline.pop(0)
                ret = self.page_add(current_page)
                if ret != self.RET_NEW:
                    return ret
                continue
            if keyword in ['group', 'group-only', 'group-except']:
                current_group = sline.pop(0)
                self.debug(f'DEBUG: ============ GROUP={current_group}')
                if 'group' not in self.pagelist[current_page]:
                    self.pagelist[current_page]['group'] = {}
                if current_group in self.pagelist[current_page]['group']:
                    self.error(f'ERROR: group {current_group} already exists')
                    continue
                self.pagelist[current_page]['group'][current_group] = {}
                if keyword == 'group-only' or keyword == 'group-except':
                    if len(sline) == 0:
                        self.error(f'ERROR: {keyword} without filter')
                        continue
                    gfilterraw = sline.pop(0)
                    gfilter = gfilterraw.split('|')
                    self.pagelist[current_page]['group'][current_group][keyword] = gfilter
                if len(sline) > 0:
                    self.pagelist[current_page]['group'][current_group]['title'] = ' '.join(sline)
                continue
            if keyword in ['dispinclude', 'netinclude', 'optional',
                           'subparent',
                           'vpage', 'vsubpage', 'vsubparent']:
                self.log(self.daemon_name, f"UNHANDLED {keyword}")
                continue
            if keyword == 'include':
                dname = sline.pop(0)
                dpath = self.etcdir + "/" + dname
                ret = self.read_hosts_file(dpath)
                if ret == self.RET_ERR:
                    return ret
                self.mtimes_hosts[dpath] = {}
                self.mtimes_hosts[dpath]["mtime"] = os.path.getmtime(dpath)
                continue
            if keyword == 'directory':
                dname = sline.pop(0)
                if dname[0] == '/':
                    dpath = dname
                else:
                    dpath = self.etcdir + "/" + dname
                try:
                    flist = os.listdir(dpath)
                except FileNotFoundError as e:
                    self.error(f"ERROR: fail to read {dpath} {str(e)}")
                    return self.RET_ERR
                self.mtimes_hosts[dpath] = {}
                self.mtimes_hosts[dpath]["mtime"] = os.path.getmtime(dpath)
                for fname in flist:
                    # avoid vim swap files
                    if re.search(".swp$", fname):
                        continue
                    npath = f"{dpath}/{fname}"
                    self.debug(f"DEBUG: will load {npath}")
                    ret = self.read_hosts_file(npath)
                    if ret == self.RET_ERR:
                        return ret
                continue
            host_ip = keyword
            host_name = sline.pop(0)
            if not is_valid_hostname(host_name):
                self.error(f"ERROR: invalid hostname {host_name}")
                continue
            self.debug("DEBUG: ip=%s host=%s" % (host_ip, host_name))
            # conn is enabled by default
            self.create_host(host_name, host_ip, sline)
            self.host_add_to_page(current_page, host_name, current_group)
        for hostname in list(self.xy_hosts):
            H = self.xy_hosts[hostname]
            if H.rhcnt < self.read_hosts_cnt:
                self.debug(f"DEBUG: read_hosts: purge {H.name}")
                self.remove_host(H)
        return self.RET_NEW

    def read_protocols(self):
        path_protocols = self.etcdir + "/protocols.cfg"
        try:
            mtime = os.path.getmtime(path_protocols)
        except FileNotFoundError as e:
            self.error(f"ERROR: fail to get mtime of {path_protocols} {str(e)}")
            return self.RET_ERR
        # self.debug(f"DEBUG: compare mtime={mtime} and time_read_protocols={self.time_read_protocols}")
        if self.time_read_protocols < mtime:
            self.time_read_protocols = mtime
        else:
            return self.RET_OK
        try:
            fprotocols = open(path_protocols, 'r')
        except FileNotFoundError:
            self.error("ERROR: cannot open protocols.cfg")
            return self.RET_ERR
        dprotocols = fprotocols.read()
        cproto = None
        P = None
        for line in dprotocols.split('\n'):
            line = re.sub(r"^\s+", "", line)
            line = re.sub(r"#.*", "", line)
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            if line[0] == '[':
                if P is not None:
                    for protoname in cproto.split('|'):
                        self.debug(f"DEBUG: register protocols {protoname}")
                        self.protocols[protoname] = P
                cproto = line.replace('[', '').replace(']', '')
                P = xy_protocol()
                continue
            if line[0:5] == 'port ':
                P.port = int(line[5:])
                continue
            if line[0:8] == 'options ':
                P.options = line[8:]
                continue
            if line[0:8] == 'expect "':
                if line[-1] != '"':
                    self.error(f"ERROR: wrong expect format for {cproto}")
                    continue
                P.expect = line[8:len(line) - 1]
                continue
            if line[0:6] == 'send "':
                if line[-1] != '"':
                    self.error(f"ERROR: wrong send format for {cproto}")
                    continue
                P.send = line[6:len(line) - 1]
                P.send = P.send.replace('\\n', '\n')
                P.send = P.send.replace('\\r', '\r')
                continue
            self.debug(f"{cproto} unhandled {line}")
        return self.RET_OK

    def find_host(self, hostname):
        if hostname in self.xy_hosts_alias:
            hostname = self.xy_hosts_alias[hostname]
        if hostname not in self.xy_hosts:
            return None
        return self.xy_hosts[hostname]

    def add_host(self, H):
        self.xy_hosts[H.name] = H

    def remove_host(self, H):
        # first remove alias
        for alias in H.aliases:
            del self.xy_hosts_alias[alias]
        del self.xy_hosts[H.name]

    def add_host_alias(self, H, alias):
        if alias in self.xy_hosts_alias:
            self.error(f"ERROR: alias {alias} already present")
            return False
        H.aliases.append(alias)
        self.xy_hosts_alias[alias] = H.name

    def remove_host_alias(self, H):
        del self.xy_hosts_alias[H.name]

    def save_hostdata(self, hostname, buf, ts):
        if self.readonly:
            return
        # TODO: like xymon check free space
        hdir = "%s/%s" % (self.xt_hostdata, hostname)
        if not os.path.exists(hdir):
            os.mkdir(hdir)
        if self.xythonmode == 0:
            hfile = "%s/%d" % (hdir, ts)
            f = open(hfile, 'w')
            f.write(buf)
            f.close()
        else:
            comp = bz2.compress(buf.encode("UTF8"))
            hfile = "%s/%d.bz2" % (hdir, ts)
            f = open(hfile, 'wb')
            f.write(comp)
            f.close()

    # initial status conn 1675773637 1675773637 0 gr - -1
    # tatus conn 1675796496 1675773637 22859 re gr 2
    # later status conn 1675845763 1675796496 49267 gr re 1
    def save_hist(self, hostname, column, color, ocolor, ts, ots, duration):
        if self.readonly:
            return
        histfile = "%s/%s" % (self.xt_histdir, hostname)
        f = open(histfile, "a+")
        f.write("%s %d %d %d %s %s %d\n" % (column, ts, ots, duration, color[0:2], ocolor[0:2], 1))
        f.close()
        hostcolpath = f"{self.xt_histdir}/{hostname}.{column}"
        newfile = False
        if not os.path.exists(hostcolpath):
            newfile = True
        f = open(hostcolpath, "a+")
        if newfile:
            f.write(f"{xytime(ts)} {color} {int(ts)}")
        else:
            f.write(f" {duration}\n{xytime(ts)} {color} {int(ts)}")
        f.close()

    def gen_column_info(self, hostname):
        color = 'green'
        H = self.find_host(hostname)
        if H is None:
            return
        cdata = f"{xytime(time.time())} - info\n"
        cdata += f"Hostname: {hostname}\n"
        if H.osversion:
            cdata += f"OS: {H.osversion}\n"
        if H.uname:
            cdata += f"OS: {H.uname}\n"
        if len(H.aliases) > 0:
            cdata += f"Aliases={H.aliases}\n"
        cdata += "IP: TODO\n"
        if H.client_version:
            cdata += f"Client S/W: {H.client_version}\n"
        cdata += f"TAGS={H.tags_known}\n"
        cdata += f"TAGS not handled {H.tags_unknown}\n"
        cdata += f"TAGS with error {H.tags_error}\n"
        for test in H.tests:
            cdata += f"TESTS {test.type}\n"
        if len(H.tags_unknown):
            color = 'yellow'
        if len(H.tags_error):
            color = 'red'
        # TODO infinite time
        self.column_update(hostname, "info", color, int(time.time()), cdata, 365 * 24 * 3600, "xythond")

    # return all cname for a host in a list
    def get_columns(self, hostname):
        print(f"DEBUG: get_columns {hostname}")
        self.sqc.execute(f'SELECT column FROM columns WHERE hostname == "{hostname}"')
        results = self.sqc.fetchall()
        if len(results) >= 1:
            allc = []
            for r in results:
                allc.append(r[0])
            return allc
        return None

    def get_column_state(self, hostname, cname):
        self.sqc.execute('SELECT * FROM columns WHERE hostname == ? AND column == ?', (hostname, cname))
        results = self.sqc.fetchall()
        if len(results) == 1:
            return results[0]
        return None

    def get_column_color(self, hostname, cname):
        col = self.get_column_state(hostname, cname)
        if col is None:
            return None
        return col[COLUMN_COLOR]

    def get_ghost_mode(self):
        ghostmode = self.xython_getvar("GHOSTMODE")
        if ghostmode is None:
            ghostmode = "ALLOW"
        return ghostmode

    def ghost(self, hostname):
        ts_start = time.time()
        if not is_valid_hostname(hostname):
            self.error(f"ERROR: ghost with invalid hostname {hostname}")
            return self.RET_ERR
        ghostmode = self.get_ghost_mode()
        if ghostmode not in ["ALLOW", "DROP", "LOG", "AUTOREGISTER"]:
            self.error(f"ERROR: invalid ghost mode {ghostmode}, fallback to ALLOW")
            # TODO I dont like this default
            ghostmode = "ALLOW"
        self.debug(f"DEBUG: ghost for {hostname} ghostmode={ghostmode}")
        if ghostmode == "DROP":
            return self.RET_OK
        if ghostmode == "LOG":
            # TODO get IP
            self.error(f"ERROR: ghost client {hostname}")
            R = {}
            R["hostname"] = hostname
            R["ts"] = ts_start
            self.ghosts.append(R)
            return self.RET_OK
        if ghostmode == "AUTOREGISTER":
            self.ghostfile = self.etcdir + "/ghosts.cfg"
            try:
                with open(self.ghostfile, "a") as f:
                    f.write(f"0.0.0.0 {hostname}\n")
            except PermissionError as e:
                self.error(f"ERROR: FAIL to write to {self.ghostfile} {str(e)}")
                return self.RET_ERR
            self.debug(f"DEBUG: AUTOREGISTER {hostname}")
            # self.read_hosts()
        # default is self.ghost == "ALLOW":
        # self.debug("DEBUG: %s not exists" % hostname)
        self.debug(f"DEBUG: GHOST ALLOW {hostname}")
        H = xy_host(hostname)
        H.hostip = hostname
        self.add_host(H)
        return self.RET_NEW

    # TODO use RET_XXX
    # return 0 if no color change
    # return 1 if color change
    # return 2 for errors
    def column_update(self, hostname, cname, color, ts, data, expire, updater):
        if cname == '':
            self.error(f'column_update: {hostname} cname is empty')
            return 2
        color_changed = False
        # self.debug(f"DEBUG: column_update {hostname} {cname} ts={ts} expire={expire}")
        color = gcolor(color)
        ts_start = time.time()
        expiretime = int(ts_start + expire)
        H = self.find_host(hostname)
        if not H:
            ret = self.ghost(hostname)
            if ret != self.RET_NEW:
                return 2
            H = self.find_host(hostname)
            if not H:
                return 2
        if H.dialup:
            if cname == 'conn':
                if color == 'red':
                    color = 'clear'
                    H.ping_success = False
                else:
                    H.ping_success = True
            if color == 'purple':
                color = 'clear'
            # handle network test for dialup host
            # if host is pingable, network tests will go red
            # if host is not pingable (due to random IP), no network test should exists
            if not H.ping_success and color == 'red' and (cname in self.protocols or cname in ["snmp", "tssh"]):
                color = 'clear'
        ackend = None
        acktime = None
        ackcause = None
        ocolor = "-"
        ots = ts
        self.sqc.execute('SELECT * FROM columns WHERE hostname == ? AND column == ?', (hostname, cname))
        results = self.sqc.fetchall()
        if len(results) > 1:
            self.error("ERROR: this is impossible")
            return 2
        if len(results) == 0:
            if color == 'purple':
                self.error("ERROR: creating a purple column")
                return 2
            # self.debug("DEBUG: create column %s on %s" % (cname, hostname))
        else:
            result = results[0]
            ocolor = result[4]
            ots = result[2]
            acktime = result[5]
            ackend = result[5]
            ackcause = result[6]
            ackmsg = result[6]
        if acktime is None:
            acktime = 0
            ackmsg = ""
        if ocolor == 'blue' and color != 'purple' and color != 'blue':
            # keep it blue
            color = 'blue'
            # keep old expire
            self.debug(f"DEBUG: BLUE {hostname} {cname} expire={expiretime} {xytime(expiretime)} oexpire={result[3]} {xytime(result[3])}")
            expiretime = int(result[3])
            # get reason
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                self.error("ERROR: keeping blue without status")
                return 2
            odata = ''.join(rdata["raw"])
            lodata = odata.split("\n\n")
            firsts = lodata[0].split(" ", 1)[1]
            # remove the first colour
            blue_header = firsts + "\n\n" + lodata[1] + "\n\n"
            data = blue_header + data
        if color == 'purple':
            if ocolor == 'purple':
                self.error("ERROR: cannot go from purple to purple")
                return 2
        # self.debug("%s %s color=%s ocolor=%s ts=%s ots=%s" % (hostname, cname, ocolor, color, ts, ots))
        if color == ocolor:
            ts = ots
        else:
            duration = ts - ots
            self.save_hist(hostname, cname, color, ocolor, ts, ots, duration)
            self.history_update(hostname, cname, ts, duration, color, ocolor)
            color_changed = True
        if color == 'purple' or (color == 'clear' and data is None):
            if data is not None:
                print("ERROR")
            # duplicate
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                self.error(f"ERROR: cannot purple {hostname}:{cname} without status, creating an empty one")
                rdata = {}
                rdata["raw"] = "statusempty"
            data = ''.join(rdata["raw"])
        # TODO not @@XYMONDCHK-V1
        # @@status#62503/karnov|1684156989.403184|172.16.1.22||karnov|lr|1684243389|red||red|1682515389|0||0||1684156916|linux||0|
        # see xymond/new-daemon.txt
        # status hostname = 4
        # status testname = 5 expire=6 logtime=1 color=7 sender=2 origin=3
        # testflags=8 prevcolor=9 changetime=10
        # acktime=11 ackmsg=12
        # disabletime=13 dismg=14
        # flapping=16
        if self.has_pika:
            if data is None:
                self.error("ERROR: column_update: data is none")
            status = f"@@status#{self.msgn}/{hostname}|{ts}|{updater}||{hostname}|{cname}|{ts}|{color}||{ocolor}|{ts}|{acktime}|{ackmsg}|0||{ts}|linux||0|\n"
            status += data
            status += '\n@@'
            self.msgn += 1
            # TODO handle error
            properties = pika.BasicProperties(expiration=str(10000))
            try:
                self.channel.basic_publish(exchange='xython-status', routing_key='', body=status, properties=properties)
            # pika.exceptions.StreamLostError: Stream connection lost: ConnectionResetError(104, 'Connection reset by peer')
            # pika.exceptions.ChannelWrongStateError: Channel is closed.
            except pika.exceptions.ChannelWrongStateError:
                # TODO what to do ?
                self.error("ERROR: pika connection closed")
                if self.channel.is_closed:
                    self.debug("DEBUG: closed")
                self.init_pika()
                self.channel.basic_publish(exchange='xython-status', routing_key='', body=status, properties=properties)

        # req = f'INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color) VALUES ("{hostname}", "{cname}", {ts}, {ts} + {expire}, "{color}")'
        self.sqc.execute('INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color, ackend, ackcause) VALUES (?, ?, ?, ?, ?, ?, ?)', (hostname, cname, ts, expiretime, color, ackend, ackcause))
        # self.sqconn.commit()
        if color == 'purple':
            # duplicate
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                return 2
            data = ''.join(rdata["data"])
        self.save_histlogs(hostname, cname, data, ts, color, updater)
        self.save_state(hostname, cname, color, int(ts), int(expiretime))
        ts_end = time.time()
        self.stat("COLUPDATE", ts_end - ts_start)
        if color_changed:
            return 1
        return 0

    def save_state(self, hostname, cname, color, ts_start, ts_expire):
        if self.xythonmode == 0:
            return
        if cname == '':
            self.error(f'save_state: {hostname} cname is empty')
            return
        expdir = f"{self.xt_state}/{hostname}"
        if not os.path.exists(expdir):
            os.mkdir(expdir)
        fexpire = f"{expdir}/{cname}"
        f = open(fexpire, 'w')
        f.write(f"{color} {ts_start} {ts_expire}")
        f.close()

    # histlog format
    # first line colorSPACEdata
    # status unchanged in
    # Message received from xxxx
    # Client data ID xxxx
    def get_histlogs(self, hostname, column, ts):
        if hostname is None or column is None or ts is None:
            return None
        try:
            if self.xythonmode == 0 or (self.xythonmode == 1 and int(self.uptime_start) > int(ts)):
                fhist = f"{self.histlogs}/{hostname}/{column}/{xytime_(int(ts))}"
            else:
                fhist = f"{self.xt_histlogs}/{hostname}/{column}/{int(ts)}"
            f = open(fhist, 'r')
        except:
            self.error(f"ERROR: Fail to open {fhist} {ts}")
            return None
        try:
            data = f.readlines()
        except:
            self.error(f"ERROR: Fail to read {fhist} {ts}")
            return None
        f.close()
        if len(data) < 4:
            self.error(f"ERROR: get_histlogs: histlog of {hostname}:{column} is too small {data}")
            return None
        ret = {}
        ret["raw"] = data.copy()
        ret["first"] = data.pop(0)
        ret["clientid"] = data.pop(-1)
        ret["sender"] = data.pop(-1)
        ret["changed"] = data.pop(-1)
        ret["data"] = data
        return ret

    def save_histlogs(self, hostname, column, buf, ts, color, updater):
        if self.readonly:
            return
        # TODO add header/footer
        # self.debug("DEBUG: save_histlogs %s %s" % (hostname, column))
        hdir = "%s/%s" % (self.xt_histlogs, hostname)
        if not os.path.exists(hdir):
            os.mkdir(hdir)
        hdir = "%s/%s/%s" % (self.xt_histlogs, hostname, column)
        if not os.path.exists(hdir):
            os.mkdir(hdir)
        hfile = "%s/%d" % (hdir, ts)
        f = open(hfile, 'w', encoding='utf-8')
        f.write("%s " % color)
        try:
            f.write(r"%s" % buf)
        except UnicodeEncodeError as e:
            self.error(f"Fail to write data for {hostname} {column} {ts} {e}")
            tbuf = buf.encode("UTF8", "replace").decode("UTF8", 'surrogateescape')
            f.write(tbuf)
        # TODO calcul
        # add a \n since buf could not have one at end
        f.write("\nstatus unchanged in 0.00 minutes\n")
        # TODO get IP
        f.write(f"Message received from {updater}\n")
        # TODO what is the purpose of this ?
        f.write(f"Client data ID {int(ts)}\n")
        f.close()

    # replacement for read_hist
    def load_state(self, hostname):
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: read_hist: {hostname} not found")
            return False
        if H.hist_read:
            return True
        self.debug(f"DEBUG: read_hist of {hostname}")
        H.hist_read = True
        expdir = f"{self.xt_state}/{hostname}"
        try:
            dirFiles = os.listdir(expdir)
        except:
            self.error(f"ERROR: fail to open {expdir}")
            return False
        for cname in dirFiles:
            if cname == "info":
                continue
            self.debug(f"DEBUG: load_state {hostname} {cname}")
            try:
                fstate = f"{expdir}/{cname}"
                f = open(fstate, 'r')
                data = f.read()
                f.close()
                # print(data)
                tokens = data.split(" ")
                if len(tokens) != 3:
                    self.error(f"ERROR: fail to load {expdir}/{cname}: invalid data")
                    continue
                color = tokens[0]
                ts_start = int(tokens[1])
                ts_expire = int(tokens[2])
                # self.debug(f"DEBUG: expire of {hostname}.{cname} is {expire} {xytime(expire)}")
                self.column_set(hostname, cname, color, ts_start, None, ts_expire)
            except:
                self.error(f"ERROR: fail to load {expdir}/{cname}")
                continue
        return True

    # read hist of a host, creating columns
    # this permit to detect current blue
    # a dropped column is detected by checking existence of host.col files BUT on my system some
    # column has host.col and are still detected as droped by xymon, how it achieves this ?
    # we could speed up reading by only checking last line of host.col BUT I want to validate
    # that I perfectly understood format of all file
    # xython TODO: create hostname subdir instead of all in one directory
    def read_hist(self, name):
        # TODO read_hist could be converted as a hist checker
        return self.load_state(name)
        H = self.find_host(name)
        if H is None:
            self.error(f"ERROR: read_hist: {name} not found")
            return False
        if H.hist_read:
            return True
        self.debug(f"DEBUG: read_hist of {name}")
        H.hist_read = True
        histdir = self.histdir
        if self.xythonmode > 0:
            histdir = self.xt_histdir
        histbase = f"{histdir}/{name}"
        try:
            fhost = open(histbase)
        except FileNotFoundError:
            self.debug(f"DEBUG: {histbase} does not exists")
            return True
        # find current columns
        hostcols = {}
        dirFiles = os.listdir(histdir)
        for hostcol in dirFiles:
            # TODO does column has a character restrictions ?
            if not re.match(r'%s\.[a-z0-9_-]+' % name, hostcol):
                continue
            self.debug(f"DEBUG: read_hist hostcol={hostcol} from {histdir} for {name}")
            # The value is "do we have saw it ?"
            column = re.sub(f'{name}.', '', hostcol)
            hostcols[column] = False

        for line in fhost:
            line = line.rstrip()
            sline = line.split(" ")
            if len(sline) != 7:
                self.error("ERROR: read_hist: wrong len")
                return False
            column = sline[0]
            if column not in hostcols:
                # self.debug(f"DEBUG: ignore dropped {name} {column}")
                continue
            if column == 'info':
                continue
            hostcols[column] = True
            # validate column name
            if not re.match(r"[a-z]", column):
                self.error("ERROR: column name %s is not good in %s" % (sline, self.histdir + name))
                return False
            tsb = int(sline[1])
            tsa = int(sline[2])
            duration = int(sline[3])
            if tsa + duration != tsb:
                self.error(f"ERROR: TS/duration in histlog invalid {sline} TSA+DUR={tsa + duration}")
            st_new = sline[4]
            st_old = sline[5]
            expire = 6 * 60
            self.debugdev("hist", "DEBUG: %s goes from %s to %s" % (column, st_old, st_new))
            # check color, if blue read histlogs
            if st_new == 'blue' or st_new == 'bl':
                self.debug(f"DEBUG: BLUE CASE {sline}")
                bbuf = self.get_histlogs(H.name, column, tsb)
                edate = bbuf['first'].replace('blue Disabled until ', '').rstrip()
                # self.debug(f"DEBUG: disable date is {edate}X")
                ets = xyts(edate, self.tz)
                expire = ets - int(time.time())
            if self.readonly:
                self.column_update(H.name, column, st_new, int(tsb), None, 3 * 60, "xython")
            else:
                self.column_set(H.name, column, st_new, tsb, expire, None)
        for column in hostcols:
            if not hostcols[column]:
                self.error(f"ERROR: remains of {name} {column}")
        return True

    # simple is for one-line data
    def do_inventory(self, hostname, section, data, simple):
        # TODO compress ?
        # self.debug(f"DEBUG: inventory for {hostname}:{section}")
        if simple:
            sha256 = data.rstrip()
        else:
            n = hashlib.sha256()
            n.update(data.encode('utf8', 'surrogateescape'))
            sha256 = n.hexdigest()
        if hostname not in self.inventory_cache:
            self.inventory_cache[hostname] = {}
        if section not in self.inventory_cache[hostname]:
            self.inventory_cache[hostname][section] = None
        if sha256 == self.inventory_cache[hostname][section]:
            # self.debug(f"INVENTORY: {section} is cached")
            return True
        idir = "%s/%s" % (self.xt_inventorydir, hostname)
        if not os.path.exists(idir):
            os.mkdir(idir)
        idir = "%s/%s/%s" % (self.xt_inventorydir, hostname, section)
        if not os.path.exists(idir):
            os.mkdir(idir)
        ifile = "%s/%s" % (idir, section)
        try:
            with open(ifile, 'r') as f:
                ih = f.read()
        except FileNotFoundError:
            # self.debug(f"DEBUG: {ifile} do not exists")
            ih = ""
        last = False
        found = False
        ihl = ih.split("\n")
        # format "TS hash"
        for line in ihl:
            if len(line) == 0:
                continue
            last = False
            line = line.rstrip()
            # self.debug(f"IVENTORY: check {line}")
            tokens = line.split(" ")
            if not simple and len(tokens) != 2:
                self.error(f"Corrupt {ifile}")
                return False
            if simple:
                v = tokens[1:]
            else:
                v = tokens[1]
            if v == sha256:
                last = True
        if last:
            return True
        self.inventory_cache[hostname][section] = sha256
        with open(ifile, 'a') as f:
            f.write(f"{time.time()} {sha256}\n")
        if simple:
            return True
        hfile = "%s/%s" % (idir, sha256)
        with open(hfile, 'w') as f:
            f.write(data)
        return True

    def gen_top_changes(self, dstart, dend):
        ts = xyevent_to_ts(dstart, self.tz)
        if ts is None:
            ts_start = 0
        else:
            ts_start = int(ts)
        ts = xyevent_to_ts(dend, self.tz)
        if ts is None:
            # TODO print error
            ts_end = 0
        else:
            ts_end = int(ts)
        hlist = self.html_header("topchanges_header")
        byhost = {}
        byservice = {}
        histdir = self.xt_histdir
        for hostname in self.xy_hosts:
            byhost[hostname] = 0
            histbase = f"{histdir}/{hostname}"
            try:
                fhost = open(histbase)
            except FileNotFoundError:
                continue
            for line in fhost:
                line = line.rstrip()
                sline = line.split(" ")
                column = sline[0]
                if column == 'info':
                    continue
                tss = int(sline[1])
                tse = int(sline[2])
                useit = False
                if tss >= ts_start and tss <= ts_end:
                    useit = True
                if tse >= ts_start and tse <= ts_end:
                    useit = True
                if not useit:
                    continue
                byhost[hostname] += 1
                if column in byservice:
                    byservice[column] += 1
                else:
                    byservice[column] = 1
        # sort values
        byhosts = []
        htotal = 0
        while len(byhosts) < 10 and len(byhost.keys()) > 0:
            cid = None
            cmax = 0
            for h in byhost:
                if byhost[h] >= cmax:
                    cmax = byhost[h]
                    cid = h
            del byhost[cid]
            v = [cid, cmax]
            byhosts.append(v)
            htotal += cmax
        hother = 0
        for h in byhost:
            hother += byhost[h]
        # print(f"byhost sorted = {byhosts} \nremains = {byhost}\nother={hother} total={htotal}")
        # sort values
        bysvcs = []
        stotal = 0
        while len(bysvcs) < 10 and len(byhost.keys()) > 0 and len(byservice) > 0:
            cid = None
            cmax = 0
            for h in byservice:
                if byservice[h] >= cmax:
                    cmax = byservice[h]
                    cid = h
            del byservice[cid]
            v = [cid, cmax]
            bysvcs.append(v)
            stotal += cmax
        sother = 0
        for h in byservice:
            sother += byservice[h]
        # print(f"byhost sorted = {bysvcs} \nremains = {byservice} \nother={sother} total={stotal}")
        hlist.append('<center><p><font size=+1></font></p><table summary="Top changing hosts and services" border=1><tr><td width=40% align=center valign=top>')
        hlist.append('<table summary="Top 10 hosts" border=0><tr><th colspan=3>Top 10 hosts</th></tr>')
        hlist.append('<tr><th align=left>Host</th><th align=left colspan=2>State changes</th></tr>')

        for h in byhosts:
            hlist.append(f'<tr><td>{h[0]}</td><td>{h[1]}</td></tr>')
        if hother > 0:
            hlist.append(f'<tr><td>Others hosts</td><td>{hother}</td></tr>')

        hlist.append(f'<tr><td colspan=3><hr width="100%"></td></tr><tr><th>Total</th><th>{htotal + hother}</th><th>&nbsp;</th></tr></table>')
        hlist.append('</td><td width=40% align=center valign=top><table summary="Top 10 services" border=0><tr><th colspan=3>Top 10 services</th></tr>')
        hlist.append('<tr><th align=left>Service</th><th align=left colspan=2>State changes</th></tr>')

        for h in bysvcs:
            hlist.append(f'<tr><td>{h[0]}</td><td>{h[1]}</td></tr>')
        if sother > 0:
            hlist.append(f'<tr><td>Others services</td><td>{sother}</td></tr>')

        hlist.append('<tr><td colspan=3><hr width="100%"></td></tr>')
        hlist.append(f'<tr><th>Total</th><th>{sother + stotal}</th><th>&nbsp;</th></tr></table></td></tr></table></center><BR><BR>')

        hlist += self.html_footer("topchanges_footer")
        html = self.html_finalize("green", hlist, "topchanges")
        return html

    def check_acks(self):
        now = time.time()
        req = f'UPDATE columns SET ackend = null WHERE ackend <= {now}'
        self.sqc.execute(req)

    def acks_dump(self):
        req = "SELECT hostname, column, ackend, ackcause FROM columns"
        self.sqc.execute(req)
        results = self.sqc.fetchall()
        print(results)

    def check_purples(self):
        ts_start = time.time()
        now = int(ts_start)
        req = f'SELECT * FROM columns WHERE expire < {now} AND color != "purple" AND color != "clear"'
        self.sqc.execute(req)
        results = self.sqc.fetchall()
        for col in results:
            hostname = col[0]
            column = col[1]
            expire = col[3]
            pdate = xytime(col[2])
            pedate = xytime(expire)
            pnow = xytime(now)
            self.debug(f"DEBUG: purplelize {hostname} {column} {expire}<{now} {pdate} {pedate} < {pnow}")
            self.column_update(hostname, column, "purple", now, None, 0, "xythond")
        ts_end = time.time()
        self.stat("PURPLE", ts_end - ts_start)
        return

    # gen all tests to be scheduled
    def gen_tests(self):
        now = int(time.time())
        self.debug("DEBUG: GEN TESTS")
        self.sqc.execute('DELETE FROM tests')
        for hostname in self.xy_hosts:
            H = self.xy_hosts[hostname]
            for T in H.tests:
                self.debug("DEBUG: gentest %s %s" % (H.name, T.type))
                # self.debug(T.urls)
                tnext = now + randint(1, 10)
                self.sqc.execute(f'INSERT OR REPLACE INTO tests(hostname, column, next) VALUES ("{H.name}", "{T.type}", {tnext})')

    def dump_tests(self):
        for T in self.tests:
            print("%s %d" % (T.name, int(T.ts)))

    def do_tssh(self, T):
        name = f"{T.hostname}_tssh"
        ctask = do_tssh.delay(T.hostname, T.urls)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def do_snmp(self, T):
        name = f"{T.hostname}_snmp"
        H = self.find_host(T.hostname)
        ctask = do_snmp.delay(T.hostname, H.gethost(), H.snmp_community, H.snmp_columns, H.oids)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def dohttp(self, T):
        name = f"{T.hostname}_http"
        ctask = dohttp.delay(T.hostname, T.urls, T.column)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def dofail(self, T):
        name = f"{T.hostname}_fail"
        ctask = task_fail.delay()
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)
        return True

    def doping(self, T):
        H = self.find_host(T.hostname)
        name = f"{T.hostname}_conn"
        self.debugdev('celery', f"DEBUG: doping for {name}")
        if name in self.celerytasks:
            self.error(f"ERROR: lagging test for {name}")
            return False
        ctask = ping.delay(T.hostname, H.gethost(), T.doipv4, T.doipv6)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)
        return True

    def do_generic_proto(self, H, T):
        name = f"{T.hostname}_{T.type}"
        if T.type not in self.protocols:
            self.error(f"ERROR: {T.type} not found in protocols")
            return None
        P = self.protocols[T.type]
        ctask = do_generic_proto.delay(T.hostname, H.gethost(), T.type, P.port, T.urls,
                                       P.send, P.expect, P.options)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def do_tests(self):
        self.celery_workers = celery.current_app.control.inspect().ping()
        if self.celery_workers is None:
            self.error("ERROR: no celery workers")
            return
        ts_start = time.time()
        now = int(time.time())
        self.sqc.execute(f'SELECT * FROM tests WHERE next < {now}')
        results = self.sqc.fetchall()
        self.log("tests", f"DEBUG: DO TESTS {len(results)}")
        if len(results) == 0:
            return
        lag = 0
        for test in results:
            hostname = test[0]
            ttype = test[1]
            self.debugdev("test", f"DEBUG: dotests {hostname} {ttype}")
            H = self.find_host(hostname)
            for T in H.tests:
                if T.type == ttype:
                    if T.type == 'fail':
                        self.dofail(T)
                    if T.type == 'conn':
                        if not self.doping(T):
                            lag += 1
                    if T.type == 'tssh':
                        self.do_tssh(T)
                    if T.type == 'snmp':
                        self.do_snmp(T)
                    if T.type == 'http':
                        self.dohttp(T)
                    if T.type in self.protocols:
                        self.do_generic_proto(H, T)
                        continue
        self.sqc.execute(f'UPDATE tests SET next = {now} + {self.NETTEST_INTERVAL} WHERE next < {now}')
        ts_end = time.time()
        self.stat("tests", ts_end - ts_start)
        self.stat("tests-lag", lag)

    def tests_rrd(self, hostname, rrds):
        for rrd in rrds:
            self.debugdev("rrd", f"DEBUG: handle RRD {rrd}")
            buf = ""
            rrdcolor = 'green'
            for obj in rrds[rrd]:
                rrdcolor = 'green'
                self.debugdev("rrd", f"DEBUG: handle {rrd} obj {obj}")
                values = rrds[rrd][obj]["values"]
                if values != "":
                    self.do_rrd(hostname, rrd, obj, rrds[rrd][obj]["dsnames"], rrds[rrd][obj]["values"], rrds[rrd][obj]["dsspecs"])
                rrdcolor = setcolor(rrds[rrd][obj]["color"], rrdcolor)
                buf += rrds[rrd][obj]["status"]
            now = time.time()
            status = f"{xytime(now)} - {rrd}\n" + buf
            self.column_update(hostname, rrd, rrdcolor, now, status, self.NETTEST_INTERVAL + 120, "xython-tests")

    def do_tests_rip(self):
        ts_start = time.time()
        self.celery_workers = celery.current_app.control.inspect().ping()
        if self.celery_workers is None:
            self.error("ERROR: no celery workers")
            return
        # RIP celery tasks
        now = int(time.time())
        for ctask in self.celtasks:
            if ctask.ready():
                status = ctask.status
                if status == 'FAILURE':
                    failed = None
                    for name in list(self.celerytasks):
                        if self.celerytasks[name] == ctask:
                            failed = name
                            del (self.celerytasks[name])
                    self.celtasks.remove(ctask)
                    self.error(f"ERROR: celery task error for {failed}")
                    # TODO better handle this problem, easy to generate by removing ping
                    try:
                        ret = ctask.get()
                    except BaseException as e:
                        self.error(f"ERROR: celery task {failed} except {e}")
                    ctask.forget()
                    continue
                ret = ctask.get()
                hostname = ret["hostname"]
                testtype = ret["type"]
                if testtype in ['snmp', 'tssh']:
                    if ret["data"] is not None:
                        self.parse_hostdata(ret["data"], f"{testtype} for {hostname}")
                if "rrds" in ret:
                    self.tests_rrd(hostname, ret["rrds"])
                column = ret["column"]
                self.debugdev('celery', f'DEBUG: result for {ret["hostname"]} \t{ret["type"]}\t{ret["color"]}')
                self.column_update(ret["hostname"], ret["column"], ret["color"], now, ret["txt"], self.NETTEST_INTERVAL + 120, "xython-tests")
                if "certs" in ret:
                    # self.debug(f"DEBUG: result for {ret['hostname']} {ret['column']} has certificate")
                    for url in ret["certs"]:
                        H = self.find_host(ret["hostname"])
                        H.certs[url] = ret["certs"][url]
                    if len(ret["certs"]):
                        self.do_sslcert(ret["hostname"])
                self.celtasks.remove(ctask)
                name = f'{ret["hostname"]}_{ret["type"]}'
                if name not in self.celerytasks:
                    self.error(f"ERROR: BUG {name} not found")
                else:
                    del (self.celerytasks[name])
                ctask.forget()
                if testtype == 'conn' and "rtt_avg" in ret:
                    self.do_rrd(hostname, column, "rtt", 'sec', ret["rtt_avg"], ['DS:sec:GAUGE:600:0:U'])
        ts_end = time.time()
        self.stat("tests-rip", ts_end - ts_start)
        self.stat("tests-remains", len(self.celtasks))
        return

    def do_sslcert(self, hostname):
        color = 'green'
        H = self.find_host(hostname)
        if H is None:
            return
        cdata = f"{xytime(time.time())} - sslcert\n"
        for url in H.certs:
            # self.debug(f"DEBUG: sslcert handle {url}")
            cdata += f"<fieldset><legend>{url}</legend>\n"
            cdata += f"{H.certs[url]['txt']}\n"
            expire = H.certs[url]["expire"]
            if expire <= H.sslalarm:
                cdata += f"&red expire in {expire} days (WARN={H.sslwarn} CRIT={H.sslalarm})\n"
                color = setcolor('red', color)
            elif expire <= H.sslwarn:
                cdata += f"&yellow expire in {expire} days (WARN={H.sslwarn} CRIT={H.sslalarm})\n"
                color = setcolor('yellow', color)
            else:
                cdata += f"&green expire in {expire} days (WARN={H.sslwarn} CRIT={H.sslalarm})\n"
            cdata += "</fieldset>\n"
        self.column_update(hostname, "sslcert", color, int(time.time()), cdata, self.NETTEST_INTERVAL + 120, "sslcert")

    # TODO hardcoded hostname
    def do_xythond(self):
        ccolor = 'green'
        now = int(time.time())
        buf = f"{xytime(now)} - xythond\n"
        for stat in self.stats:
            color = '&clear'
            moy = round(self.stats[stat]["cumul"] / self.stats[stat]["count"], 4)
            smin = round(self.stats[stat]["min"], 4)
            smax = round(self.stats[stat]["max"], 4)
            cur = round(self.stats[stat]["last"], 4)
            if stat == 'tests-lag' and cur > 0:
                color = '&yellow'
            buf += f'{color} {stat:13} CURRENT={cur:10} COUNT={self.stats[stat]["count"]:10} MOY={moy:8} MIN={smin:8} MAX={smax:8}\n'
        uptime = now - self.uptime_start
        uptimem = int(uptime / 60)
        if uptimem < 1:
            uptimem = 1
        buf += f"Up since {xytime(self.uptime_start)} ({xydhm(self.uptime_start, now)})\n"
        if "COLUPDATE" in self.stats:
            if "count" in self.stats["COLUPDATE"]:
                buf += f'UPDATE/m: {int(self.stats["COLUPDATE"]["count"] / uptimem)}\n'
        # for worker in self.celery_workers:
        #    print(worker)
        self.sqc.execute('SELECT count(DISTINCT hostname) FROM columns')
        results = self.sqc.fetchall()
        buf += f"Hosts: {results[0][0]}\n"
        self.sqc.execute('SELECT count(next) FROM tests')
        results = self.sqc.fetchall()
        buf += f"Active tests: {results[0][0]}\n"
        buf += f"hosts.cfg mtime {xytime(self.time_read_hosts)}\n"
        buf += f"xymonserver.cfg mtime {xytime(self.time_read_xserver_cfg)}\n"
        buf += f"Local time: {xytime(now)} TZ={self.tz}\n"
        nghost = 0
        for ghost in self.ghosts:
            if ghost["ts"] + 300 < now:
                self.ghosts.remove(ghost)
                continue
            if nghost == 0:
                buf += "Ghost reports:\n"
            nghost += 1
            buf += f'&nbsp;reported host {ghost["hostname"]}\n'
            ccolor = setcolor('yellow', ccolor)
        if nghost > 0:
            buf += f'Current ghost mode {self.get_ghost_mode()}\n\n'
        for elog in self.errors:
            if elog["ts"] + 300 < now:
                self.errors.remove(elog)
                continue
            buf += f'&red ERROR: {elog["msg"]}\n'
            ccolor = 'red'
        self.column_update(socket.gethostname(), "xythond", ccolor, now, buf, self.XYTHOND_INTERVAL + 60, "xythond")

    def scheduler(self):
        now = time.time()
        if now > self.ts_tests + 5:
            self.do_tests()
            self.do_tests_rip()
            self.stat("ts_tests", time.time() - now)
            self.ts_tests = now
        if now > self.ts_check + 1:
            self.check_purples()
            self.check_acks()
            self.ts_check = now
        if now > self.ts_xythond + self.XYTHOND_INTERVAL:
            xythond_start = time.time()
            self.do_xythond()
            self.stat("xythond", time.time() - xythond_start)
            self.ts_xythond = now

        if now > self.ts_page + self.GENPAGE_INTERVAL:
            ts_start = time.time()
            self.gen_htmls()
            ts_end = time.time()
            self.stat("HTML", ts_end - ts_start)
            self.ts_page = now
        if now > self.ts_read_configs + 60:
            ts = time.time()
            self.read_configs()
            self.stat("read_configs", time.time() - ts)
            self.ts_read_configs = now
        if now > self.ts_genrrd + self.RRD_INTERVAL:
            self.gen_rrds()
            self.ts_genrrd = now
        if self.has_pika:
            try:
                self.channel.basic_publish(exchange='xython-ping', routing_key='', body="PING")
            # pika.exceptions.StreamLostError: Stream connection lost: ConnectionResetError(104, 'Connection reset by peer')
            except:
                self.error("PIKA TODO")
        self.stat("SCHEDULER", time.time() - now)

    def analysis_disk(self, ltoks, name):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        rd = {}
        rd["ignore"] = False
        rd["warn"] = 90
        rd["panic"] = 95
        # we need at least 2 tokens
        if len(ltoks) < 2:
            self.error(f'ERROR: missing {name} parameter in {ltoks}')
            ret['err'] = True
            return ret
        pattern = ltoks.pop(0)
        # spetial * case
        if pattern == '*':
            pattern = '%.*'
        # self.debug(f"DEBUG: {name} pattern {pattern}")
        rd["fs"] = pattern
        # either numeric, IGNORE, or numericU
        arg = ltoks.pop(0)
        if arg.isnumeric():
            # self.debug(f"DEBUG: {name} warn {arg}")
            rd["warn"] = int(arg)
        elif arg == 'IGNORE':
            # self.debug(f"DEBUG: {name} IGNORE")
            ret['ltoks'] = ltoks
            rd["ignore"] = True
            ret['setting'] = rd
            return ret
        elif arg[-1] == 'U':
            # self.debug(f"DEBUG: {name} warnU {arg}")
            arg = arg[:-1]
            rd["warn"] = int(arg)
        else:
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            ret['setting'] = rd
            return ret
        if len(ltoks) == 0:
            self.error(f'ERROR: missing {name} panic parameter in {ltoks}')
            ret['err'] = True
            return ret
        arg = ltoks.pop(0)
        if arg.isnumeric():
            # self.debug(f"DEBUG: {name} panic {arg}")
            rd["panic"] = int(arg)
        elif arg[-1] == 'U':
            # self.debug(f"DEBUG: {name} panicU {arg}")
            arg = arg[:-1]
            rd["panic"] = int(arg)
        else:
            self.error(f'ERROR: bad {name} panic parameter in {ltoks}')
            ret['err'] = True
            ret['ltoks'] = ltoks
            return ret
        ret['ltoks'] = ltoks
        ret['setting'] = rd
        return ret

    def analysis_load(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        rl = {}
        # we need at least 2 tokens
        if len(ltoks) < 2:
            self.error(f'ERROR: missing 2 LOAD parameters in {ltoks}')
            ret['err'] = True
            return ret
        arg = ltoks.pop(0)
        try:
            warn = float(arg)
        except ValueError:
            self.error(f'ERROR: LOAD bad warn in {ltoks}')
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            ret['err'] = True
            return ret
        rl["loadwarn"] = warn
        # self.debug(f"DEBUG: LOAD warn {warn}")
        arg = ltoks.pop(0)
        try:
            panic = float(arg)
        except ValueError:
            self.error(f'ERROR: LOAD bad panic in {arg}')
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            ret['err'] = True
            return ret
        # self.debug(f"DEBUG: LOAD panic {panic}")
        rl["loadpanic"] = panic
        ret['ltoks'] = ltoks
        ret['setting'] = rl
        return ret

    def analysis_memory(self, ltoks, name):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        rm = {}
        # we need at least 2 tokens
        if len(ltoks) < 2:
            self.error(f'ERROR: missing {name} parameter in {ltoks}')
            ret['err'] = True
            return ret
        arg = ltoks.pop(0)
        if len(arg) == 0:
            self.error(f'ERROR: {name} bad warn in {ltoks}')
            ret['err'] = True
            return ret
        try:
            warn = int(arg)
        except ValueError:
            self.error(f'ERROR: {name} bad warn in {ltoks}')
            ret['err'] = True
            return ret
        # self.debug(f"DEBUG: {name} warn {warn}")
        rm["warn"] = warn
        arg = ltoks.pop(0)
        if len(arg) == 0:
            self.error(f'ERROR: {name} bad panic in {ltoks}')
            ret['err'] = True
            return ret
        try:
            panic = int(arg)
        except ValueError:
            self.error(f'ERROR: {name} bad panic in {ltoks}')
            ret['err'] = True
            return ret
        rm["panic"] = panic
        # self.debug(f"DEBUG: {name} panic {panic}")
        ret['ltoks'] = ltoks
        ret["setting"] = rm
        return ret

    def analysis_up(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        ru = {}
        # we need at least 2 tokens
        if len(ltoks) == 0:
            self.error(f'ERROR: missing UP parameter in {ltoks}')
            ret['err'] = True
            return ret
        arg = ltoks.pop(0)
        bootlimit = xydelay(arg)
        if bootlimit is None:
            self.error(f'ERROR: UP bad bootlimit in {ltoks}')
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            ret['err'] = True
            return ret
        # self.debug(f"DEBUG: UP bootlimit {bootlimit}")
        ru["bootlimit"] = bootlimit
        if len(ltoks) == 0:
            ret['ltoks'] = ltoks
            ret["setting"] = ru
            return ret
        arg = ltoks.pop(0)
        toolonglimit = xydelay(arg)
        if toolonglimit is None:
            self.error(f'ERROR: UP bad toolonglimit in {ltoks}')
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            ret['err'] = True
            return ret
        # self.debug(f"DEBUG: UP toolonglimit {toolonglimit}")
        ru["toolonglimit"] = toolonglimit
        if len(ltoks) == 0:
            ret['ltoks'] = ltoks
            ret["setting"] = ru
            return ret
        color = ltoks.pop(0)
        if not is_valid_color(color):
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            return ret
        self.debug(f"DEBUG: UP color {color}")
        ru["upcolor"] = color
        ret['ltoks'] = ltoks
        ret["setting"] = ru
        return ret

    def analysis_log(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        if len(ltoks) < 2:
            self.error(f'ERROR: missing LOG parameter in {ltoks}')
            ret['err'] = True
            return ret
        logfilename = ltoks.pop(0)
        pattern = ltoks.pop(0)
        while len(ltoks) > 0:
            arg = ltoks.pop(0)
            if arg == "OPTIONAL":
                TODO = 1
            elif "COLOR=" in arg:
                TODO = 1
            elif "IGNORE=" in arg:
                TODO = 1
            else:
                ltoks.insert(0, arg)
                ret['ltoks'] = ltoks
                return ret
        ret['ltoks'] = ltoks
        return ret

    def analysis_port(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        if len(ltoks) == 0:
            self.error(f'ERROR: missing PORT parameter in {ltoks}')
            ret['err'] = True
            return ret
        rp = xy_rule_port()
        while len(ltoks):
            arg = ltoks.pop(0)
            args = arg.split('=')
            if len(args) != 2:
                ret['err'] = True
                return ret
            left = args[0].upper()
            value = args[1]
            if len(left) == 0 or len(value) == 0:
                ret['err'] = True
                return ret
            if left == 'LOCAL':
                if value[0] == '%':
                    rp.local = value[1:]
                else:
                    rp.local = value
            elif left == 'EXLOCAL':
                self.debug("DEBUG: PORT: {left} is not handled yet")
            elif left == 'REMOTE':
                self.debug("DEBUG: PORT: {left} is not handled yet")
            elif left == 'EXREMOTE':
                self.debug("DEBUG: PORT: {left} is not handled yet")
            elif left == 'STATE':
                if value[0] == '%':
                    rp.rstate = value[1:]
                else:
                    rp.state = value
            elif left == 'EXSTATE':
                self.debug("DEBUG: PORT: {left} is not handled yet")
            elif left == 'MIN':
                try:
                    rp.min = int(value)
                except ValueError:
                    ret['err'] = True
                    return ret
            elif left == 'MAX':
                try:
                    rp.max = int(value)
                except ValueError:
                    ret['err'] = True
                    return ret
            elif left == 'COLOR':
                rp.color = value
            elif left == 'TRACK':
                self.debug("DEBUG: PORT: {left} is not handled yet")
            elif left == 'TEXT':
                rp.text = value
            else:
                self.error(f"ERROR: PORT: unknow keyword {left}")
                ret['err'] = True
                return ret
        ret['ltoks'] = ltoks
        ret['setting'] = rp
        return ret

    def analysis_proc(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        if len(ltoks) == 0:
            self.error(f'ERROR: missing PROC parameter in {ltoks}')
            ret['err'] = True
            return ret
        rp = xy_rule_proc()
        pattern = ltoks.pop(0)
        # self.debug(f"DEBUG: PROC pattern {pattern}")
        rp.name = pattern
        if len(ltoks) == 0:
            ret['ltoks'] = ltoks
            ret['setting'] = rp
            return ret
        tmin = ltoks.pop(0)
        if not tmin.isnumeric():
            self.error(f'ERROR: PROC invalid min value in {ltoks}')
            ltoks.insert(0, tmin)
            ret['ltoks'] = ltoks
            ret['err'] = True
            return ret
        # self.debug(f"DEBUG: PROC min {tmin}")
        rp.min = int(tmin)
        if len(ltoks) == 0:
            ret['ltoks'] = ltoks
            ret['setting'] = rp
            return ret
        tmax = ltoks.pop(0)
        if not tmax.isnumeric():
            self.error(f'ERROR: PROC invalid max value in {ltoks}')
            ltoks.insert(0, tmax)
            ret['ltoks'] = ltoks
            ret['err'] = True
            return ret
        # self.debug(f"DEBUG: PROC max {tmax}")
        rp.max = int(tmax)
        while len(ltoks) > 0:
            # now we can have color/TEXT/TRACK
            n = ltoks.pop(0)
            if "TEXT=" in n:
                self.debug(f"DEBUG: PROC TEXT")
                args = n.split('=')
                arg = args[1]
                if len(arg) == 0:
                    self.error(f'ERROR: PROC: nothing after TEXT=')
                    ret['ltoks'] = ltoks
                    ret['err'] = True
                    return ret
                rp.text = arg
            elif "TRACK=" in n:
                self.debug(f"DEBUG: PROC TRACK")
            elif is_valid_color(n):
                # self.debug(f"DEBUG: PROC color {n}")
                rp.color = n
            else:
                ltoks.insert(0, n)
                ret['ltoks'] = ltoks
                ret['setting'] = rp
                return ret
        ret['ltoks'] = ltoks
        ret['setting'] = rp
        return ret

    def analysis_sensor(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        rs = {}
        rs["ignore"] = False
        if len(ltoks) < 3:
            self.error(f'ERROR: missing SENSOR parameter in {ltoks}')
            ret['err'] = True
            return ret
        rs["adapter"] = ltoks.pop(0)
        rs["sname"] = ltoks.pop(0)
        rs["warn"] = SENSOR_DISABLE
        rs["panic"] = SENSOR_DISABLE
        rs["mwarn"] = SENSOR_DISABLE
        rs["mpanic"] = SENSOR_DISABLE
        arg = ltoks.pop(0)
        if arg == 'IGNORE':
            rs["ignore"] = True
            ret['ltoks'] = ltoks
            ret['setting'] = rs
            return ret
        if len(ltoks) == 0:
            self.error(f'ERROR: missing SENSOR parameter in {ltoks}')
            ret['err'] = True
            return ret
        try:
            rs["warn"] = float(arg)
        except ValueError:
            self.error(f'ERROR: SENSOR: invalid warn value {arg}')
            ret['err'] = True
            return ret
        arg = ltoks.pop(0)
        try:
            rs["panic"] = float(arg)
        except ValueError:
            self.error(f'ERROR: SENSOR: invalid warn value {arg}')
            ret['err'] = True
            return ret
        if len(ltoks) < 2:
            ret['ltoks'] = ltoks
            ret['setting'] = rs
            return ret
        arg = ltoks.pop(0)
        try:
            rs["mwarn"] = float(arg)
        except ValueError:
            # we cannot know if it is bad or a selector
            ltoks.insert(0, arg)
            ret['ltoks'] = ltoks
            ret['setting'] = rs
            return ret
        arg = ltoks.pop(0)
        try:
            rs["mpanic"] = float(arg)
        except ValueError:
            self.error(f'ERROR: SENSOR: invalid min panic value {arg}')
            ret['err'] = True
            return ret
        ret['ltoks'] = ltoks
        ret['setting'] = rs
        return ret

    def analysis_svc(self, ltoks):
        ret = {}
        ret['err'] = False
        ret['ltoks'] = ltoks
        if len(ltoks) < 1:
            self.error(f'ERROR: missing SVC parameter in {ltoks}')
            ret['err'] = True
            return ret
        servicename = ltoks.pop(0)
        self.debug(f"DEBUG: SVC: found servicename {servicename}")
        while len(ltoks) > 0:
            arg = ltoks.pop(0)
            if "startup=" in arg:
                self.debug(f"DEBUG: SVC: found startup {arg}")
                TODO = 1
            elif "status=" in arg:
                self.debug(f"DEBUG: SVC: found status {arg}")
                TODO = 1
            else:
                self.debug("DEBUG: SVC: {arg} not part of us")
                ltoks.insert(0, arg)
                ret['ltoks'] = ltoks
                return ret
        ret['ltoks'] = ltoks
        return ret


    # grammar [setting][rule][rule]*
    def read_analysis2(self):
        mtime = os.path.getmtime(f"{self.etcdir}/analysis.cfg")
        # self.debug(f"DEBUG: read_analysis: compare mtime={mtime} and {H.time_read_analysis}")
        if self.time_read_analysis < mtime:
            self.time_read_analysis = mtime
        else:
            return self.RET_OK
        # TODO reset all rules
        self.rules["DISK"] = xy_rule_disks()
        self.rules["INODE"] = xy_rule_disks()
        self.rules["PORT"] = []
        self.rules["PROC"] = []
        self.rules["MEMPHYS"] = None
        self.rules["MEMACT"] = None
        self.rules["MEMSWAP"] = None
        self.rules["CPU"] = None
        self.rules["SENSOR"] = None
        if self.rules["SENSOR"] is None:
            self.rules["SENSOR"] = xy_rule_sensors()
        self.rules["SENSOR"].add("DEFAULT C 50 60 10 0")
        # self.rules["SENSOR"].add("DEFAULT J 400 500 0 0")
        self.rules["SENSOR"].add("DEFAULT A 30 50 0 0")
        self.rules["SENSOR"].add("DEFAULT W 300 500 0 0")
        self.rules["SENSOR"].add("DEFAULT % 100 200 10 0")
        self.rules["SENSOR"].add("DEFAULT V 1000 2000 -1 -2")
        self.rules["SENSOR"].add("DEFAULT RPM 4000 5000 100 0")
        for hostname in self.xy_hosts:
            H = self.xy_hosts[hostname]
            H.rules["CPU"] = None
            H.rules["DISK"] = xy_rule_disks()
            H.rules["INODE"] = xy_rule_disks()
            H.rules["MEMPHYS"] = None
            H.rules["MEMACT"] = None
            H.rules["MEMSWAP"] = None
            H.rules["PROC"] = []
            H.rules["PORT"] = []
            H.rules["SENSOR"] = None
        f = open(f"{self.etcdir}/analysis.cfg", 'r')
        selector = None
        for line in f:
            line = line.rstrip()
            line = re.sub(r"#.*", "", line)
            line = re.sub(r"\s+", " ", line)
            line = re.sub(r"^\s+", "", line)
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            setting = None
            settingname = None
            ltoks = tokenize(line)
            # self.debug(f"===============START with {ltoks}")
            keyword = ltoks.pop(0)
            if keyword == 'DEFAULT':
                # self.debug("DEBUG: SPETIAL DEFAULT selector")
                selector = 'DEFAULT'
                continue
            if '=' not in keyword:
                # read a setting
                # print(f"{keyword} is a setting")
                if keyword == 'PORT':
                    ret = self.analysis_port(ltoks)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = 'PORT'
                elif keyword == 'PROC':
                    ret = self.analysis_proc(ltoks)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = 'PROC'
                elif keyword == 'DISK' or keyword == 'INODE':
                    ret = self.analysis_disk(ltoks, keyword)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = keyword
                elif keyword == 'LOAD':
                    ret = self.analysis_load(ltoks)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = 'LOAD'
                elif keyword in ['MEMSWAP', 'MEMACT', 'MEMPHYS']:
                    ret = self.analysis_memory(ltoks, keyword)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = keyword
                elif keyword == 'UP':
                    ret = self.analysis_up(ltoks)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = "UP"
                elif keyword == 'SENSOR':
                    ret = self.analysis_sensor(ltoks)
                    if ret["err"]:
                        continue
                    ltoks = ret["ltoks"]
                    setting = ret["setting"]
                    settingname = "SENSOR"
                elif keyword == 'LOG':
                    ret = self.analysis_log(ltoks)
                    if ret["err"]:
                        continue
                    self.debugdev("todo", f"TODO: LOG")
                    ltoks = ret["ltoks"]
                elif keyword == 'SVC':
                    ret = self.analysis_svc(ltoks)
                    if ret["err"]:
                        continue
                    self.debugdev("todo", f"TODO: SVC")
                    ltoks = ret["ltoks"]
                else:
                    self.error(f"ERROR: unknow keyword {keyword}")
            else:
                ltoks.insert(0, keyword)
            # now only selector rule
            selector_new = None
            while len(ltoks) > 0:
                keyword = ltoks.pop(0)
                ks = keyword.split("=")
                keyword = ks[0]
                if len(ks) != 2:
                    self.error(f"ERROR: no data after {keyword}= ltoks={ltoks}")
                    continue
                data = ks[1]
                if len(data) == 0:
                    self.error(f"ERROR: no data after {keyword}= ltoks={ltoks}")
                    continue
                if keyword == "HOST":
                    if selector_new is None:
                        selector_new = host_selector()
                    if data[0] == '*':
                        selector_new.all = True
                    elif data[0] == '%':
                        selector_new.setregex(data)
                    elif "," in data:
                        for hostname in data.split(","):
                            selector_new.hosts.append(hostname)
                    else:
                        selector_new.hosts.append(data)
                elif keyword == "EXHOST":
                    if selector_new is None:
                        selector_new = host_selector()
                    if data[0] == '%':
                        selector_new.setregex(data, exclude=True)
                    elif "," in data:
                        for hostname in data.split(","):
                            selector_new.exhosts.append(hostname)
                    else:
                        selector_new.exhosts.append(data)
                elif keyword == "CLASS":
                    if selector_new is None:
                        selector_new = host_selector()
                    selector_new.xclass.append(data)
                elif keyword == "EXCLASS":
                    if selector_new is None:
                        selector_new = host_selector()
                    selector_new.exclass.append(data)
                else:
                    self.error(f"ERROR: unknow selector {keyword}")
                    continue
            if selector_new is not None:
                selector = selector_new
            if setting:
                if selector is None:
                    self.error(f"ERROR: no selector")
                    continue
                # self.debug(f"DEBUG: apply setting {settingname} via selector {selector}")
                if selector == 'DEFAULT':
                    if settingname in ['DISK', 'INODE']:
                        self.rules[settingname].add2(setting["fs"], setting["ignore"], setting["warn"], setting["panic"])
                    elif settingname == 'UP':
                        if self.rules["CPU"] is None:
                            self.rules["CPU"] = xy_rule_cpu()
                        self.rules["CPU"].upset = True
                        self.rules["CPU"].bootlimit = setting["bootlimit"]
                        if "toolonglimit" in setting:
                            self.rules["CPU"].toolonglimit = setting["toolonglimit"]
                        if "upcolor" in setting:
                            self.rules["CPU"].upcolor = setting["upcolor"]
                    elif settingname == 'LOAD':
                        if self.rules["CPU"] is None:
                            self.rules["CPU"] = xy_rule_cpu()
                        self.rules["CPU"].loadset = True
                        self.rules["CPU"].loadwarn = setting["loadwarn"]
                        self.rules["CPU"].loadwarn = setting["loadpanic"]
                    elif settingname in ['MEMSWAP', 'MEMACT', 'MEMPHYS']:
                        self.rules[settingname] = xy_rule_mem()
                        self.rules[settingname].warn = setting["warn"]
                        self.rules[settingname].panic = setting["panic"]
                    else:
                        self.error(f"ERROR: unsupported {settingname} in DEFAULT")
                    continue
                # print(setting)
                # selector.dump()
                for hostname in self.xy_hosts:
                    H = self.xy_hosts[hostname]
                    ret = selector.match(H)
                    # print(f"MATCHING {H.name} {ret}")
                    if ret and settingname:
                        if settingname == 'PORT':
                            #H.rules["PORT"].append(setting)
                            H.add_rule_port(setting)
                        elif settingname == 'PROC':
                            H.add_rule_proc(setting)
                        elif settingname in ["DISK", "INODE"]:
                            H.rules[settingname].add2(setting["fs"], setting["ignore"], setting["warn"], setting["panic"])
                        elif settingname == 'LOAD':
                            if H.rules["CPU"] is None:
                                H.rules["CPU"] = xy_rule_cpu()
                            H.rules["CPU"].loadset = True
                            H.rules["CPU"].loadwarn = setting["loadwarn"]
                            H.rules["CPU"].loadwarn = setting["loadpanic"]
                        elif settingname == 'UP':
                            if H.rules["CPU"] is None:
                                H.rules["CPU"] = xy_rule_cpu()
                            H.rules["CPU"].upset = True
                            H.rules["CPU"].bootlimit = setting["bootlimit"]
                            if "toolonglimit" in setting:
                                H.rules["CPU"].toolonglimit = setting["toolonglimit"]
                            if "upcolor" in setting:
                                H.rules["CPU"].upcolor = setting["upcolor"]
                        elif settingname in ['MEMSWAP', 'MEMACT', 'MEMPHYS']:
                            H.rules[settingname] = xy_rule_mem()
                            H.rules[settingname].warn = setting["warn"]
                            H.rules[settingname].panic = setting["panic"]
                        elif settingname == 'SENSOR':
                            if H.rules["SENSOR"] is None:
                                H.rules["SENSOR"] = xy_rule_sensors()
                            H.rules["SENSOR"].add2(setting["adapter"], setting["sname"],
                                setting["ignore"],
                                setting["warn"],
                                setting["panic"],
                                setting["mwarn"],
                                setting["mpanic"])
                        else:
                            self.error(f"ERROR: unknow settingname {settingname}")

    def rrd_pathname(self, cname, ds):
        if ds == 'la':
            return 'la'
        if cname not in ['disk', 'inode']:
            return f"{cname}.{ds}"
        if ds == '/':
            return cname + ',root'
        return cname + ds.replace('/', ',').replace(' ', '_')

    def rrd_label(self, path, column):
        if path == f'{column},root':
            return '/'
        return path.replace(f"{column}.", '').replace(column, '').replace(',', '/').replace('.rrd', '')

    def rrd_color(self, i):
        if i < 0:
            i = 0
        if i < len(RRD_COLOR):
            return RRD_COLOR[i]
        return '000000'

    def load_rrddefinitions_cfg(self):
        prrddef = f"{self.etcdir}/rrddefinitions.cfg"
        try:
            mtime = os.path.getmtime(prrddef)
        except FileNotFoundError:
            self.error(f"ERROR: fail to get mtime of {prrddef}")
            return self.RET_ERR
        if self.time_read_rrddef < mtime:
            self.time_read_rrddef = mtime
        else:
            return self.RET_OK
        try:
            rrddef = open(prrddef, 'r')
        except:
            self.error(f"ERROR: cannot open {prrddef}")
            return self.RET_ERR
        lines = rrddef.readlines()
        section = None
        for line in lines:
            line = line.rstrip()
            line = line.lstrip()
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            if line[0] == '[':
                if ']' not in line:
                    self.error(f"ERROR: invalid line in {prrddef} {line}")
                    continue
                section = line.split('[')[1]
                section = section.split(']')[0]
                if section == '':
                    section = 'default'
                self.rrddef[section] = {}
                self.rrddef[section]["info"] = []
                continue
            if section is None:
                continue
            self.debugdev("rrddef", f"DEBUG: load_graphs: {section} {line}")
            self.rrddef[section]["info"].append(line)
        if 'default' not in self.rrddef:
            self.error(f"ERROR: didnt found a default section in {prrddef}")
            return self.RET_ERR
        return self.RET_OK

    def load_graphs_cfg(self):
        pgraphs = f"{self.etcdir}/graphs.cfg"
        try:
            mtime = os.path.getmtime(pgraphs)
        except FileNotFoundError:
            return self.RET_ERR
        if self.time_read_graphs < mtime:
            self.time_read_graphs = mtime
        else:
            return self.RET_OK
        try:
            fgraphs = open(pgraphs, 'r')
        except:
            self.error(f"ERROR: cannot open {pgraphs}")
            return self.RET_ERR
        lines = fgraphs.readlines()
        section = None
        for line in lines:
            line = line.rstrip()
            line = line.lstrip()
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            if line[0] == '[':
                if ']' not in line:
                    self.error(f"ERROR: invalid line in {pgraphs} {line}")
                    continue
                section = line.split('[')[1]
                section = section.split(']')[0]
                self.graphscfg[section] = {}
                self.graphscfg[section]["info"] = []
                continue
            if section is None:
                continue
            tokens = line.split(" ")
            keyword = tokens.pop(0)
            if keyword == 'YAXIS':
                self.graphscfg[section]['YAXIS'] = ' '.join(tokens)
                continue
            if keyword == 'TITLE':
                self.graphscfg[section]['TITLE'] = ' '.join(tokens)
                continue
            if keyword == 'FNPATTERN':
                self.graphscfg[section]['FNPATTERN'] = tokens[0]
                continue
            self.debugdev("loadgraph", f"DEBUG: load_graphs: {section} {line}")
            self.graphscfg[section]["info"].append(line)

    # TODO we can generate RRD while writing to it https://www.mail-archive.com/rrd-users@lists.oetiker.ch/msg13016.html
    def gen_rrd(self, hostname):
        basedir = f"{self.xt_rrd}/{hostname}"
        rrdbuf = f"{xytime(time.time(), self.tz)} - xrrd\n"
        color = 'green'
        allrrds = os.listdir(basedir)
        if 'sensor' in allrrds:
            adapters = os.listdir(f"{basedir}/sensor/")
            for adapter in adapters:
                rrd_sensors = os.listdir(f"{basedir}/sensor/{adapter}/")
                for rrd_sensor in rrd_sensors:
                    allrrds.append(f"sensor/{adapter}/{rrd_sensor}")
        # print(f"DEBUG: allrrds={allrrds}")
        now = time.time()
        for rrd in allrrds:
            mtime = os.path.getmtime(f"{basedir}/{rrd}")
            tdiff = now - mtime
            if tdiff > 3600:
                rrdbuf += f"&yellow {rrd} is not updated since {xydhm(mtime, now)}\n"
        self.debugdev("rrd", f"GENERATE RRD FOR {hostname}")
        for graph in self.graphscfg:
            # TODO find how xymon uses multi
            if "-multi" in graph:
                continue
            rrdlist = []
            if 'FNPATTERN' in self.graphscfg[graph]:
                rrdpattern = self.graphscfg[graph]["FNPATTERN"]
                for rrd in os.listdir(f"{self.xt_rrd}/{hostname}/"):
                    if re.match(rrdpattern, rrd):
                        rrdlist.append(rrd)
            else:
                rrdpath = f'{self.xt_rrd}/{hostname}/{graph}.rrd'
                if os.path.exists(rrdpath):
                    rrdlist.append(f"{graph}.rrd")
            if graph == 'sensor':
                for rrd in allrrds:
                    if 'sensor/' in rrd:
                        rrdlist.append(rrd)
            if len(rrdlist) == 0:
                continue
            if graph not in self.rrd_column:
                self.rrd_column[graph] = [graph]
            self.debugdev('rrd', f"GENERATE RRD FOR {hostname} with {graph} {rrdlist}")
            basedir = f"{self.wwwdir}/{hostname}"
            if not os.path.exists(basedir):
                os.mkdir(basedir)
                os.chmod(basedir, 0o755)
            pngpath = f"{self.wwwdir}/{hostname}/{graph}.png"
            if 'RRDWIDTH' in self.xymonserver_cfg:
                width = self.xymonserver_cfg['RRDWIDTH']
            else:
                width = self.RRDWIDTH
            if 'RRDHEIGHT' in self.xymonserver_cfg:
                height = self.xymonserver_cfg['RRDHEIGHT']
            else:
                height = self.RRDHEIGHT
            base = [pngpath,
                    f'--width={width}', f'--height={height}',
                    '--vertical-label="% Full"',
                    '--start=end-96h'
                    ]
            if 'YAXIS' in self.graphscfg[graph]:
                base.append(f'--vertical-label={self.graphscfg[graph]["YAXIS"]}')
            else:
                base.append('--vertical-label="unset"')
            if 'TITLE' in self.graphscfg[graph]:
                base.append(f'--title={self.graphscfg[graph]["TITLE"]} on {hostname}')
            else:
                base.append(f'--title={graph} on {hostname}')
            i = 0
            sensor_adapter = None
            for rrd in rrdlist:
                # a RRD could be used more than once
                if rrd in allrrds:
                    allrrds.remove(rrd)
                fname = str(rrd.replace(".rrd", ""))
                rrdfpath = f"{self.xt_rrd}/{hostname}/{rrd}"
                label = self.rrd_label(fname, graph)
                info = rrdtool.info(rrdfpath)
                template = self.graphscfg[graph]["info"]
                if graph == 'sensor':
                    adapter = os.path.dirname(rrd).split('/')[-1]
                    # print(f"DEBUG: sensor_rrd: adapter is {adapter}")
                    # remove adapter name
                    label = re.sub('/.*/', '', label)
                if graph == 'sensor' and sensor_adapter != adapter:
                    # print(f"DEBUG: sensor_rrd: add comment {adapter}")
                    sensor_adapter = adapter
                    base.append(f'COMMENT:{adapter}\\n')
                label = label.ljust(20)
                # print(f"DEBUG: label is {label}")
                for line in template:
                    for dsname in self.get_ds_name(info):
                        line = line.replace('@RRDDS@', dsname)
                    line = line.replace('@COLOR@', self.rrd_color(i))
                    line = line.replace('@RRDIDX@', f"{i}")
                    line = line.replace('@RRDFN@', rrdfpath)
                    if graph == 'la':
                        line = line.replace('la.rrd', rrdfpath)
                    line = line.replace('@RRDFN@', rrdfpath)
                    line = line.replace('@RRDPARAM@', f"{label}")
                    base.append(line)
                i += 1
            rrdup = xytime(time.time(), self.tz).replace(':', '\\:')
            base.append(f'COMMENT:Updated\\: {rrdup}')
            try:
                # ret = rrdtool.graph(base)
                # TODO check this ret
                rrdbuf += f"&green generate graph from {rrd} with template={graph}\n"
            except rrdtool.OperationalError as e:
                rrdbuf += f"&red Failed to generate RRD from {rrd} with template={graph} {e}\n"
                color = 'red'
            # os.chmod(pngpath, 0o644)
        # TODO try to handle sensor in a generic way
        if "sensor" in allrrds:
            allrrds.remove("sensor")
        if len(allrrds) > 0:
            for rrd in allrrds:
                rrdbuf += f"&yellow some RRD are not handled {rrd}\n"
            color = setcolor('yellow', color)
        self.column_update(hostname, "xrrd", color, int(time.time()), rrdbuf, self.RRD_INTERVAL + 60, "xython-rrd")

    def gen_rrds(self):
        if not has_rrdtool:
            return True
        ts_start = time.time()
        # self.debug("GEN RRDS")
        hosts = os.listdir(f"{self.xt_rrd}")
        for hostname in hosts:
            self.gen_rrd(hostname)
        self.stat("GENRRD", time.time() - ts_start)

    def gen_cgi_rrd(self, hostname, service, action):
        rrdlist = []
        basedir = f"{self.xt_rrd}/{hostname}"
        self.debug(f"DEBUG: gen_cgi_rrd {hostname} {service}")
        if service not in self.graphscfg:
            return f'Status: 400 Bad Request\n\nERROR: {service} not found in graphs.cfg'
        if not os.path.exists(basedir):
            return f'Status: 400 Bad Request\n\nERROR: {basedir} not found'
        if 'FNPATTERN' in self.graphscfg[service]:
            rrdpattern = self.graphscfg[service]["FNPATTERN"]
            for rrd in os.listdir(basedir):
                self.debugdev("rrd", f"CHECK {rrd} vs {rrdpattern}<br>")
                if re.match(rrdpattern, rrd):
                    rrdlist.append(rrd)
        else:
            rrdpath = f'{basedir}/{service}.rrd'
            if os.path.exists(rrdpath):
                rrdlist.append(f"{service}.rrd")
        if service == 'sensor':
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
            return 'Status: 400 Bad Request\n\nERROR: RRD list is empty'
        if 'RRDWIDTH' in self.xymonserver_cfg:
            width = self.xymonserver_cfg['RRDWIDTH']
        else:
            width = self.RRDWIDTH
        if 'RRDHEIGHT' in self.xymonserver_cfg:
            height = self.xymonserver_cfg['RRDHEIGHT']
        else:
            height = self.RRDHEIGHT
        base = ['-',
                f'--width={width}', f'--height={height}',
                '--vertical-label="% Full"',
                '--start=end-96h'
                ]
        if 'RRDGRAPHOPTS' in self.xymonserver_cfg:
            for rrdgopt in self.xymonserver_cfg['RRDGRAPHOPTS'].split(' '):
                base.append(rrdgopt)
        if 'YAXIS' in self.graphscfg[service]:
            base.append(f'--vertical-label={self.graphscfg[service]["YAXIS"]}')
        else:
            base.append('--vertical-label="unset"')
        if 'TITLE' in self.graphscfg[service]:
            base.append(f'--title={self.graphscfg[service]["TITLE"]} on {hostname}')
        else:
            base.append(f'--title={service} on {hostname}')
        i = 0
        sensor_adapter = None
        for rrd in rrdlist:
            fname = str(rrd.replace(".rrd", ""))
            rrdfpath = f"{basedir}/{rrd}"
            label = self.rrd_label(fname, 'conn')
            info = rrdtool.info(rrdfpath)
            template = self.graphscfg[service]["info"]
            if service == 'sensor':
                adapter = os.path.dirname(rrd).split('/')[-1]
            # print(f"DEBUG: sensor_rrd: adapter is {adapter}")
            # remove adapter name
                label = re.sub('/.*/', '', label)
            # print(f"DEBUG: sensor_rrd: add comment {adapter}")
            if service == 'sensor' and sensor_adapter != adapter:
                sensor_adapter = adapter
                base.append(f'COMMENT:{adapter}\\n')
            label = label.ljust(20)
            # print(f"DEBUG: label is {label}<br>")
            for line in template:
                for dsname in self.get_ds_name(info):
                    # print(f"DEBUG: dsname={dsname}<br>")
                    line = line.replace('@RRDDS@', dsname)
                    line = line.replace('@COLOR@', self.rrd_color(i))
                    line = line.replace('@RRDIDX@', f"{i}")
                    line = line.replace('@RRDFN@', rrdfpath)
                if service == 'la':
                    line = line.replace('la.rrd', rrdfpath)
                line = line.replace('@RRDFN@', rrdfpath)
                line = line.replace('@RRDPARAM@', f"{label}")
                base.append(line)
            i += 1
            # rrdup = xytime(time.time()).replace(':', '\\:')
            # base.append(f'COMMENT:Updated\\: {rrdup}')
        # print("==================<br>")
        # print(base)
        # print('<br>')
        try:
            ret = rrdtool.graphv(base)
        # TODO check this ret
        except rrdtool.OperationalError as e:
            self.error(f"Fail to generate RRD {str(e)}")
            return f'Status: 400 Bad Request\n\nERROR: {str(e)}'
        return b"Content-type: image/png\r\n\r\n" + ret['image']

    # give a DS name from a sensor name
    def rrd_getdsname(self, sname):
        dsname = sname
        dsname = dsname.replace(".", '_')
        dsname = dsname.replace("+", 'plus')
        dsname = dsname.replace(" ", '_')
        # dsname is 19 char max
        if len(dsname) > 19:
            dsname = dsname.replace(" ", '')
        return dsname[:19]

    def get_ds_name(self, info):
        r = []
        for k in info.keys():
            if len(k) > 4:
                if k[-4:] == 'type':
                    ds = k.split('[')[1].split(']')[0]
                    r.append(ds)
        return r

    def do_rrd(self, hostname, rrdname, obj, dsname, value, dsspec):
        # self.debug(f"DEBUG: do_rrd for {hostname} {rrdname} {obj} {dsname} {value}")
        if not has_rrdtool:
            return False
        fname = self.rrd_pathname(rrdname, obj)
        rrdpath = f"{self.xt_rrd}/{hostname}"
        if not os.path.exists(rrdpath):
            os.mkdir(rrdpath)
            os.chmod(rrdpath, 0o755)
        rrdfpath = f"{self.xt_rrd}/{hostname}/{fname}.rrd"
        if not os.path.exists(rrdfpath):
            self.debug(f"DEBUG: do_rrd create for {hostname} rrdname={rrdname} dsname={dsname} value={value}")
            if rrdname in self.rrddef:
                self.debugdev("rrd", f"DEBUG: got RRA from {rrdname}")
                rras = self.rrddef[rrdname]["info"]
            elif 'default' in self.rrddef:
                self.debugdev("rrd", "DEBUG: got RRA from default")
                rras = self.rrddef['default']["info"]
            else:
                self.error("DEBUG: RRD create this should not happen")
                self.debugdev("rrd", f"DEBUG: {self.rrddef}")
                # this should not happen
                rras = "RRA:AVERAGE:0.5:1:1200"
            self.debug(f"Create RRD with {rras}")
            try:
                rrdtool.create(rrdfpath, "--start", "now", "--step", "60", rras, dsspec)
            except rrdtool.OperationalError as e:
                self.error(f"ERROR: fail to create RRD for {hostname} {rrdname} {str(e)}")
                self.debug(dsname)
                self.debug(value)
                return False
        self.debugdev("rrd", f"DEBUG: update RRD {rrdpath} for {dsname} value={value}")
        rrdtool.update(rrdfpath, f'-t{dsname}', f"N:{value}")
        return True

    def do_sensor_rrd(self, hostname, adapter, sname, value):
        # self.debug(f"DEBUG: do_sensor_rrd for {hostname} {adapter} {sname} {value}")
        if not has_rrdtool:
            return True
        fname = self.rrd_pathname('sensor', sname)
        rrdpath = f"{self.xt_rrd}/{hostname}"
        if not os.path.exists(rrdpath):
            os.mkdir(rrdpath)
        rrd_dpath = f"{self.xt_rrd}/{hostname}/sensor"
        if not os.path.exists(rrd_dpath):
            os.mkdir(rrd_dpath)
        rrd_dpath = f"{self.xt_rrd}/{hostname}/sensor/{adapter}"
        if not os.path.exists(rrd_dpath):
            os.mkdir(rrd_dpath)
        rrdfpath = f"{rrd_dpath}/{fname}.rrd"
        dsname = self.rrd_getdsname(sname)
        # self.debug(f"DEBUG: create {rrdfpath} with dsname={dsname}")
        if not os.path.exists(rrdfpath):
            if "sensor" in self.rrddef:
                self.debugdev("rrd", "DEBUG: got RRA from sensor")
                rras = self.rrddef["sensor"]["info"]
            elif 'default' in self.rrddef:
                self.debugdev("rrd", "DEBUG: got RRA from default")
                rras = self.rrddef['default']["info"]
            else:
                self.error("DEBUG: RRD create this should not happen")
                self.debugdev("rrd", f"DEBUG: {self.rrddef}")
                # this should not happen
                rras = "RRA:AVERAGE:0.5:1:1200"
            try:
                rrdtool.create(rrdfpath, "--start", "now", "--step", "60",
                               rras, f"DS:{dsname}:GAUGE:600:-280:5000")
            except rrdtool.OperationalError as e:
                self.error(f"ERROR: fail to create RRD for {hostname} {sname} {str(e)}")
                self.debug(dsname)
                self.debug(value)
                return False
        else:
            try:
                info = rrdtool.info(rrdfpath)
            except SystemError as e:
                self.error(f"ERROR: fail to info RRD for {hostname} {sname}: {str(e)}")
                return False
            allds = self.get_ds_name(info)
            # print(f"DEBUG: already exists with {allds} we have {dsname}")
            if dsname not in allds:
                rrdtool.tune(rrdfpath, f"DS:{dsname}:GAUGE:600:-280:5000")
        try:
            self.debugdev('rrd', f"DEBUG: update {hostname} {sname} {dsname} {value}")
            rrdtool.update(rrdfpath, f'-t{dsname}', f"N:{value}")
        except rrdtool.OperationalError as e:
            self.error(f"ERROR: fail to update RRD for {hostname} {sname}: {str(e)}")
            return False
        return True

    # return 0 if no color change
    # return 1 on color change
    # return 2 on error
    def parse_free(self, hostname, buf, sender):
        ts_start = time.time()
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_free: host is None for {hostname}")
            return 2
        now = int(time.time())
        # self.debug(f"DEBUG: parse_free for {hostname}")
        # TODO handle other OS case
        color = 'green'
        sbuf = f"{xytime(now, self.tz)} - Memory OK\n"
        sbuf += "          Memory        Used       Total      Percentage\n"

        for memtype in ["MEMPHYS", "MEMACT", "MEMSWAP"]:
            if H.rules[memtype] is not None:
                ret = H.rules[memtype].memcheck(buf, memtype)
            elif self.rules[memtype] is not None:
                ret = self.rules[memtype].memcheck(buf, memtype)
            sbuf += ret["txt"]
            color = setcolor(ret["color"], color)
            rrdmemtype = 'real'
            if memtype == 'MEMACT':
                rrdmemtype = 'actual'
            if memtype == 'MEMSWAP':
                rrdmemtype = 'swap'
            self.do_rrd(hostname, 'memory', rrdmemtype, 'realmempct', ret['v'], ['DS:realmempct:GAUGE:600:0:U'])

        sbuf += buf
        ret = self.column_update(hostname, "memory", color, now, sbuf, self.ST_INTERVAL + 60, sender)
        self.stat("PARSEFREE", time.time() - ts_start)
        return ret

    # TODO Machine has been up more than 0 days
    def parse_uptime(self, hostname, buf, sender):
        now = int(time.time())
        color = 'green'
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_uptime: host is None for {hostname}")
            return 2
        udisplay = re.sub(r"^.*up ", "up", buf)
        sbuf = f"{xytime(now, self.tz)} {udisplay}\n"
        # Check with global rules
        gret = self.rules["CPU"].cpucheck(buf)
        self.do_rrd(hostname, 'la', 'la', 'la', gret['la'], ['DS:la:GAUGE:600:0:U'])
        # check gret not None
        if H.rules["CPU"] is not None:
            # check with dedicated host rules
            ret = H.rules["CPU"].cpucheck(buf)
        if H.rules["CPU"] is not None and H.rules["CPU"].loadset and ret is not None:
            color = setcolor(ret["LOAD"]["color"], color)
            sbuf += ret["LOAD"]["txt"]
        else:
            color = setcolor(gret["LOAD"]["color"], color)
            sbuf += gret["LOAD"]["txt"]
        if H.rules["CPU"] is not None and H.rules["CPU"].upset and ret is not None:
            color = setcolor(ret["UP"]["color"], color)
            sbuf += ret["UP"]["txt"]
        else:
            color = setcolor(gret["UP"]["color"], color)
            sbuf += gret["UP"]["txt"]
        sbuf += buf
        ret = self.column_update(hostname, "cpu", color, now, sbuf, self.ST_INTERVAL + 60, sender)
        return ret

    def parse_ps(self, hostname, buf, sender):
        ts_start = time.time()
        now = int(ts_start)
        color = 'green'
        sbuf = f"{xytime(now, self.tz)} - procs Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_ps: host is None for {hostname}")
            return 2
        sline = buf.split("\n")
        for procrule in self.rules["PROC"]:
            ret = procrule.check(sline)
            sbuf += ret["txt"] + '\n'
            if color == 'green':
                color = ret["color"]
        for procrule in H.rules["PROC"]:
            ret = procrule.check(sline)
            sbuf += ret["txt"] + '\n'
            if color == 'green':
                color = ret["color"]
        sbuf += buf
        ts_end = time.time()
        self.stat("parseps", ts_end - ts_start)
        ret = self.column_update(hostname, "procs", color, now, sbuf, self.ST_INTERVAL + 60, sender)
        return ret

    # TODO
    def parse_mdstat(self, hostname, buf, sender):
        now = int(time.time())
        color = 'green'
        sbuf = f"{xytime(now, self.tz)} - mdstat Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_mdstat: host is None for {hostname}")
            return 2
        sline = buf.split("\n")
        mdname = None
        mdcolor = 'clear'
        nummd = 0
        for line in sline:
            if len(line) < 1:
                if mdname is not None:
                    color = setcolor(mdcolor, color)
                    sbuf += "</fieldset>\n"
                mdname = None
                continue
            if line[0] == ' ':
                if "recovery =" in line or "reshape =" in line:
                    mdcolor = 'yellow'
                    sbuf += f"{line}\n&yellow {mdname} is rebuilding\n"
                    continue
                md = re.search(r"\s+[0-9]+ blocks.*\[([0-9]+/[0-9]+)\] \[([U_]+)\]", line)
                if md is not None:
                    nums = md.group(1)
                    numss = nums.split('/')
                    if len(numss) != 2:
                        sbuf += f"{line}\n"
                        self.error(f'ERROR: invalid mdstat line {line}')
                        continue
                    need = int(numss[0])
                    have = int(numss[1])
                    if have == need:
                        sbuf += f'{line}\n&green {mdname} is ok\n'
                    if have < need:
                        sbuf += f'{line}\n&red {mdname} is missing devices\n'
                        mdcolor = 'red'
                    continue
                sbuf += f"{line}\n"
                continue
            if mdname is not None:
                color = setcolor(mdcolor, color)
                sbuf += "</fieldset>\n"
            mdname = None
            mdcolor = 'green'
            md = re.search(r"^([a-zA-Z0-9]+)\s:", line)
            if md is None:
                sbuf += f"{line}\n"
                continue
            mdname = md.group(1)
            if mdname in ['Personalities', 'unused devices']:
                sbuf += f"{line}\n"
                mdname = None
                continue
            nummd += 1
            sbuf += f"<fieldset><legend>{mdname}</legend>\n{line}\n"
        if nummd == 0:
            return 0
        ret = self.column_update(hostname, self.colnames["mdstat"], color, now, sbuf, self.ST_INTERVAL + 120, sender)
        return ret

    # TODO
    def parse_ports(self, hostname, buf, sender):
        now = int(time.time())
        color = 'clear'
        sbuf = f"{xytime(now, self.tz)} - ports Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_ports: host is None for {hostname}")
            return 2
        sline = buf.split("\n")
        texts = []
        for port in H.rules["PORT"]:
            text = port.text
            # self.debug(f"DEBUG: handle port {text} {texts}")
            if text is not None:
                if text in texts:
                    sbuf += f"Ignore {text}\n"
                    continue
                texts.append(text)
            ret = port.check(sline)
            sbuf += ret["txt"] + '\n'
            color = setcolor(ret["color"], color)
        for port in self.rules["PORT"]:
            text = port.text
            # self.debug(f"DEBUG: handle port {text} {texts}")
            if text is not None:
                if text in texts:
                    sbuf += f"Ignore {text}\n"
                    continue
                texts.append(text)
            ret = port.check(sline)
            sbuf += ret["txt"] + '\n'
            color = setcolor(ret["color"], color)
        sbuf += buf
        sbuf += f'RULES {H.rules["PORT"]}'
        ret = self.column_update(hostname, "ports", color, now, sbuf, self.ST_INTERVAL + 60, sender)
        return ret

# TODO self detect high/crit min/max from output
# like Core 0:        +46.0 C  (high = +82.0 C, crit = +102.0 C)
# should detect a second warn=82 and red=102
    def parse_sensors(self, hostname, buf, sender):
        ts_start = time.time()
        now = int(ts_start)
        adapter = None
        color = 'green'
        sbuf = f"{xytime(now, self.tz)} - sensors Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error("ERROR: parse_sensors: host is None")
            return 2
        sline = buf.split("\n")
        for line in sline:
            if len(line) == 0:
                adapter = None
                continue
            if line[0] == ' ':
                # TODO some crit/emerg are on thoses lines
                continue
            # self.debug(f"DEBUG: SENSOR: check {line}XX")
            if len(line) > 0 and ':' not in line:
                # self.debug(f"DEBUG: SENSOR: {hostname} adapter={line}")
                adapter = line
                sbuf += '<br>\n' + line + '\n'
                continue
            if adapter is not None:
                sbuf += line + '\n'
                if "SENSOR" in H.rules and H.rules["SENSOR"] is not None:
                    ret = H.rules["SENSOR"].check(adapter, line)
                else:
                    ret = None
                if ret is None:
                    # self.debug("DEBUG: use global rules")
                    ret = self.rules["SENSOR"].check(adapter, line)
                if ret is not None:
                    sbuf += ret["txt"] + '\n'
                    color = setcolor(ret["color"], color)
                if ret is not None and 'v' in ret:
                    self.do_sensor_rrd(hostname, adapter, ret['sname'], ret['v'])
                continue
            # self.debug(f"DEBUG: SENSOR ignored {line}XX")
        ts_end = time.time()
        self.stat("parsesensor", ts_end - ts_start)
        ret = self.column_update(hostname, "sensor", color, now, sbuf, self.ST_INTERVAL + 60, sender)
        return ret

    def parse_df(self, hostname, buf, inode, sender):
        now = int(time.time())
        if inode:
            column = 'inode'
            S = "INODE"
        else:
            column = 'disk'
            S = "DISK"
        color = 'green'
        sbuf = f"{xytime(now, self.tz)} - disk Ok\n"

        H = self.find_host(hostname)
        if H is None:
            self.error("ERROR: parse_disk: host is None")
            return 2
        sline = buf.split("\n")
        for line in sline:
            pct = None
            mnt = None
            if len(line) == 0:
                continue
            if line[0] != '/':
                continue
            if H.rules[S] is not None:
                ret = H.rules[S].check(line)
            else:
                ret = None
            if ret is not None:
                sbuf += ret["txt"] + '\n'
                color = setcolor(ret["color"], color)
                if "pct" in ret:
                    pct = ret["pct"]
                    mnt = ret["mnt"]
            else:
                ret = self.rules[S].check(line)
                if ret is not None:
                    sbuf += ret["txt"] + '\n'
                    color = setcolor(ret["color"], color)
                    if "pct" in ret:
                        pct = ret["pct"]
                        mnt = ret["mnt"]
            if pct is not None:
                self.do_rrd(hostname, column, mnt, 'pct', pct, ['DS:pct:GAUGE:600:0:100'])
        sbuf += buf
        ret = self.column_update(hostname, column, color, now, sbuf, self.ST_INTERVAL + 60, sender)
        return ret

    def parse_status(self, msg):
        # self.debug(f"DEBUG: parse_status from {msg['addr']}")
        hdata = msg["buf"]
        column = None
        # only first line is important
        lines = hdata.split("\n")
        line = lines[0]
        toks = line.split(" ")
        hostcol = toks[1]
        color = toks[2]
        hc = hostcol.split(".")
        if len(hc) < 2:
            return False
        column = hc[-1]
        del (hc[-1])
        hostname = ".".join(hc)
        if color not in COLORS:
            self.error(f"ERROR: invalid color {color}")
            return False
        expire = 30 * 60
        wstatus = toks[0].replace("status", "")
        if len(wstatus) > 0:
            # either group and/or +x
            if wstatus[0] == '+':
                expire = xydelay(wstatus)
        self.debug(f"DEBUG: HOST.COL={line} {hostname} {column} color={color} expire={expire}")
        # remove status+x host.col color
        remove = f"status{wstatus} {hostname}.{column} {color} "
        hdata = hdata.replace(remove, "")
        if column is not None:
            self.column_update(hostname, column, color, int(time.time()), hdata, expire, msg["addr"])
        return False

    def do_ack(self, hostname, cname, expire, why):
        req = f'UPDATE columns SET ackcause="{why}", ackend={expire} WHERE hostname="{hostname}" AND column="{cname}" AND color != "green"'
        self.sqc.execute(req)
        # TODO check if we changed at least one line

    def read_acks(self):
        if self.xythonmode == 0:
            return self.read_xymon_acks()
        now = time.time()
        dirFiles = os.listdir(self.xt_acks)
        for fack in dirFiles:
            self.debug(f"DEBUG: read ack {fack}")
            f = open(f"{self.xt_acks}/{fack}")
            line = f.read()
            f.close()
            tokens = line.split(" ")
            hostname = tokens.pop(0)
            if not is_valid_hostname(hostname):
                self.error(f"ERROR: read_acks: hostname {hostname} is not valid")
                continue
            cname = tokens.pop(0)
            if not is_valid_column(cname):
                self.error(f"ERROR: read_acks: column {cname} is not valid")
                continue
            start = float(tokens.pop(0))
            expire = float(tokens.pop(0))
            if expire < now:
                self.debug("DEBUG: expired ack")
                # TODO ignore it and delete it
                continue
            why = ' '.join(tokens)
            self.debug(f"DEBUG: ack {hostname}.{cname} until {xytime(expire, self.tz)} why={why}")
            self.do_ack(hostname, cname, expire, why)

    def store_ack(self, hostname, column, start, expire, msg):
        fname = f"{self.xt_acks}/{xytime_(start, self.tz)}"
        f = open(fname, 'w')
        f.write(f"{hostname} {column} {start} {expire} {msg}\n")
        f.close()

    # TODO
    def read_xymon_acks(self):
        try:
            # TODO XYMONTMP
            f = open("/var/tmp/xymon/xymond.chk")
        except:
            return self.RET_ERR
        data = f.readlines()
        f.close()
        for line in data:
            # print("======================================")
            # print(line)
            tokens = line.split('|')
            if tokens[0] != '@@XYMONDCHK-V1':
                print(f"Invalid header {tokens[0]}")
                continue
            if tokens[1] != "":
                print(tokens)
                continue
            hostname = tokens[2]
            column = tokens[3]
            sender = tokens[4]
            ackmsg = tokens[17]
            bluetime = int(tokens[11])
            bluemsg = tokens[16]
            if bluemsg != "":
                print(f"DEBUG: acks: for {hostname}.{column} by={sender} reason={bluemsg} end={bluetime}")
            if ackmsg == "":
                continue
            print("========")
            ackend = int(tokens[12])
            print(f"DEBUG: acks: for {hostname}.{column} by={sender} reason={ackmsg} end={ackend}")
            now = time.time()
            print(ackend - now)
            print((ackend - now) / 60)
            print((ackend - now) / (3600 * 24))

# format acknowledge hostname column duration cause
    def parse_acknowledge(self, msg):
        self.debug(f"ACK ACTION {msg}")
        lmsg = msg.split(" ")
        if len(lmsg) < 4:
            return False
        t = lmsg.pop(0)
        if t != "acknowledge":
            self.error(f"ERROR: I should found acknowledge (got {t})")
            return False
        who = lmsg.pop(0)
        # now find the hostname
        lwho = who.split('.')
        testname = lwho.pop()
        hostname = '.'.join(lwho)
        self.debug(f"DEBUG: I will acknowledge {hostname} columns:{testname}")
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: unknow hostname (got {hostname})")
            return False
        howlong = lmsg.pop(0)
        howlongs = xydelay(howlong)
        # TODO the real expire in DB could be some secs after
        now = time.time()
        expire = now + howlongs
        if howlongs is None:
            self.error(f"ERROR: invalid duration {howlong}")
            return False
        why = " ".join(lmsg)
        self.debug(f"DEBUG: I will acknowledge {who} for {howlongs}s due to {why}")

        columns = []
        if testname == '*':
            columns = self.get_columns(hostname)
            if columns is None:
                return False
        else:
            columns.append(testname)
        for cname in columns:
            self.do_ack(hostname, cname, expire, why)
            self.store_ack(hostname, cname, now, expire, why)
        return True

    def parse_disable(self, msg):
        self.debug(f"DISABLE ACTION {msg}")
        dstart = int(time.time())
        lmsg = msg.split(" ")
        if len(lmsg) < 4:
            return False
        t = lmsg.pop(0)
        if t != "disable":
            self.error(f"ERROR: I should found disable (got {t})")
            return False
        who = lmsg.pop(0)
        # now find the hostname
        lwho = who.split('.')
        testname = lwho.pop()
        hostname = '.'.join(lwho)
        self.debug(f"DEBUG: I will disable {hostname} columns:{testname}")
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: unknow hostname (got {hostname})")
            return False
        howlong = lmsg.pop(0)
        howlongs = xydelay(howlong)
        # TODO the real expire in DB could be some secs after
        expire = dstart + howlongs
        if howlongs is None:
            self.error(f"ERROR: invalid duration {howlong}")
            return False
        why = " ".join(lmsg)
        self.debug(f"DEBUG: I will disable {who} for {howlongs}s due to {why}")

        columns = []
        if testname == '*':
            columns = self.get_columns(hostname)
            if columns is None:
                return False
        else:
            columns.append(testname)
        for cname in columns:
            blue_status = f"Disabled until {xytime(expire, self.tz)}\n\n{why}\n\nStatus message when disabled follows:\n\n"
            result = self.get_column_state(hostname, cname)
            if result is None:
                self.error("ERROR: cannot disable an empty column")
                return False
            ots = result[2]
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                return False
            data = ''.join(rdata["raw"])
            blue_status += data
            self.column_update(hostname, cname, "blue", dstart, blue_status, howlongs, "bluter")
        return True

    def parse_dmesg(self, hostname, hdata, sender):
        now = time.time()
        color = 'green'
        state  = f"{xytime(now, self.tz)} - dmesg Ok\n<p>"
        try:
            f = open(self.etcdir + '/dmesg.regex')
            patterns = f.read().splitlines()
            f.close()
        except FileNotFoundError:
            patterns = []
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: fail to find {hostname} for dmesg")
            return False
        curr_level = None
        lastts = 0
        for line in hdata.split("\n"):
            if len(line) <= 1:
                continue
            if line[0] != '#':
                self.error(f"ERROR: invalid dmesg line {line}")
                continue
            if line[1] == '#':
                if curr_level is not None:
                    state += "</fieldset>"
                curr_level = line[2:]
                if curr_level not in ['emerg', 'alert', 'crit', 'err', 'warn', 'notice']:
                    self.error(f"ERROR: unknow dmesg level {curr_level}")
                state += f"<fieldset><legend>{curr_level}</legend>\n<br>"
                continue
            if curr_level is None:
                state += "&red BUG no level\n"
            oline = line
            ts = re.search(r'(^#\[\s*)([0-9]+\.[0-9]+)(\]\s)', line)
            if ts is None:
                its = 0
            else:
                its = float(ts.group(2))
                tsa = ts.group(1) + ts.group(2) + ts.group(3)
                line = line.replace(tsa, '')
            # filter also the [Txxx] [Cxxx]
            kid = re.search(r'^\[\s*[CT][0-9]+\]\s', line)
            if kid is not None:
                line = line.replace(kid.group(0), '')
            if line[1] == ' ':
                # TODO multi line, found only on rpi kernel or crashes
                # ignore it for now
                self.debugdev('dmesg', f"DEBUG: dmesg: ignore multi part {line}")
                continue
            ignore = False
            for p in patterns:
                if ignore:
                    continue
                if re.search(p, line):
                    ignore = True
            if ignore:
                state += f"&clear {line}<br>\n"
            else:
                state += f"&red {line}\n"
                if curr_level in ['emerg', 'alert', 'crit', 'err']:
                    color = setcolor("red", color)
                else:
                    color = setcolor("yellow", color)
            if lastts < its:
                lastts = its
                # TODO unack if new message appears ?
        H.dmesg_last_ts = lastts
        state += "</fieldset>"
        tend = time.time()
        state += f"</p>Seconds: {tend - now}"
        self.column_update(hostname, "dmesg", color, int(tend), state, 60 * 60, sender)
        return True

    def parse_hostdata(self, hdata, addr):
        hostname = None
        section = None
        save_hostdata = False
        buf = ""
        ret = self.parse_collector(hdata)
        if ret is None:
            return
        hostname = ret[0]
        hdata += "\n[end]\n"
        for line in hdata.split("\n"):
            line = line.rstrip()
            if len(line) == 0:
                continue
            # self.debug(f"DEBUG: section={section} line={line}")
            if line[0] == '[' and line[len(line) - 1] == ']':
                if section is not None:
                    handled = False
                    if section == '[collector:]':
                        handled = True
                    if section == '[free]':
                        handled = True
                        ret = self.parse_free(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[uptime]':
                        handled = True
                        ret = self.parse_uptime(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[df]':
                        handled = True
                        ret = self.parse_df(hostname, buf, False, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[inode]':
                        handled = True
                        ret = self.parse_df(hostname, buf, True, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[ports]':
                        handled = True
                        ret = self.parse_ports(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[ss]':
                        handled = True
                        ret = self.parse_ports(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[ps]':
                        handled = True
                        ret = self.parse_ps(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[lmsensors]':
                        handled = True
                        ret = self.parse_sensors(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[mdstat]':
                        handled = True
                        ret = self.parse_mdstat(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[dmesg]':
                        handled = True
                        ret = self.parse_dmesg(hostname, buf, addr)
                        if ret >= 1:
                            save_hostdata = True
                    if section == '[clientversion]':
                        handled = True
                        H = self.find_host(hostname)
                        if H is not None:
                            H.client_version = buf
                        self.gen_column_info(hostname)
                    if section == '[uname]':
                        handled = True
                        H = self.find_host(hostname)
                        if H is not None:
                            H.uname = buf
                        self.gen_column_info(hostname)
                        ret = self.do_inventory(hostname, "uname", buf, True)
                    if section == '[cpumicrocode]':
                        handled = True
                        ret = self.do_inventory(hostname, "cpumicrocode", buf, True)
                    if section == '[lsmod]':
                        handled = True
                        ret = self.do_inventory(hostname, "lsmod", buf, False)
                    if section == '[lspci]':
                        handled = True
                        ret = self.do_inventory(hostname, "lspci", buf, False)
                    if section == '[dpkg]':
                        handled = True
                        ret = self.do_inventory(hostname, "dpkg", buf, False)
                    if section == '[rpm]':
                        handled = True
                        ret = self.do_inventory(hostname, "rpm", buf, False)
                    if section == '[dmidecode]':
                        handled = True
                        ret = self.do_inventory(hostname, "dmidecode", buf, False)
                    if section == '[osversion]':
                        handled = True
                        H = self.find_host(hostname)
                        if H is not None:
                            H.osversion = buf
                        self.gen_column_info(hostname)
                    # if not handled:
                    #    self.debug(f"DEBUG: section {section} not handled")
                section = line
                buf = ""
                continue
            if section in ['[uptime]', '[ps]', '[df]', '[collector:]', '[inode]', '[free]', '[ports]', '[lmsensors]', '[mdstat]', '[ss]', '[clientversion]', '[uname]', '[osversion]', '[dmesg]', '[lsmod]', '[lspci]', '[dpkg]', '[rpm]', '[cpumicrocode]', '[dmidecode]']:
                buf += line
                buf += '\n'
        if hostname is not None:
            if save_hostdata:
                self.save_hostdata(hostname, hdata, time.time())
        else:
            self.error("ERROR: invalid client data without hostname")

    def handle_net_message(self, buf, addr):
        ret = {}
        # if buf is None:
        #    buf = C["buf"]
        sbuf = buf.split(" ")
        cmd = sbuf[0]
        ret["cmd"] = cmd
        # print(f"DEBUG: cmd={cmd}")
        if cmd[0:4] == 'PING':
            self.debug("PING PONG")
            ret["send"] = "PONG\n"
            ret["done"] = 1
        if cmd[0:4] == 'DROP' or cmd[0:4] == 'drop':
            self.debug("DEBUG: DROP action")
            self.handle_drop(buf)
            ret["done"] = 1
        elif cmd == 'GETPAGE':
            page = sbuf[1]
            data = self.html_page(page)
            ret["send"] = data
            ret["done"] = 1
            # try:
            #    C.send(data.encode("UTF8"))
            # except BrokenPipeError as error:
            #    self.error("Client get away")
            #    pass
        elif cmd == 'GETSTATUS':
            if len(sbuf) < 3:
                ret["send"] = f"ERROR: need more parameters\n"
                ret["done"] = 1
                return ret
            hostname = sbuf[1]
            service = sbuf[2].rstrip()
            if not is_valid_column(service):
                ret["send"] = f"ERROR: service has invalid name {service}\n"
                ret["done"] = 1
                return ret
            if len(sbuf) > 3:
                ts = xyts_(sbuf[3], self.tz)
            else:
                res = self.sqc.execute('SELECT ts FROM columns WHERE hostname == ? AND column == ?', (hostname, service))
                results = self.sqc.fetchall()
                if len(results) != 1:
                    ret["send"] = f"ERROR: no service named {service}\n"
                    ret["done"] = 1
                    return ret
                ts = results[0][0]
            data = self.gen_html("svcstatus", hostname, service, ts)
            ret["send"] = data
            ret["done"] = 1
        elif cmd[0:6] == "status":
            msg = {}
            msg["buf"] = buf
            msg["addr"] = 'local'
            self.parse_status(msg)
            ret["done"] = 1
        elif cmd == "acknowledge":
            self.parse_acknowledge(buf)
            ret["done"] = 1
        elif cmd == "disable":
            self.parse_disable(buf)
            ret["done"] = 1
        elif cmd == 'TOPCHANGES':
            if len(sbuf) < 3:
                ret["send"] = 'Status: 400 Bad Request\n\nERROR: not enough arguments'
                ret["done"] = 1
                return ret
            r = self.gen_top_changes(sbuf[1], sbuf[2].rstrip())
            if type(r) is str:
                ret["send"] = r
            else:
                ret["bsend"] = r
            ret["done"] = 1
        elif cmd == 'GETRRD':
            self.debug(sbuf)
            if len(sbuf) < 4:
                ret["send"] = 'Status: 400 Bad Request\n\nERROR: not enough arguments'
                ret["done"] = 1
                return ret
            r = self.gen_cgi_rrd(sbuf[1], sbuf[2], sbuf[3])
            if type(r) is str:
                ret["send"] = r
            else:
                ret["bsend"] = r
            ret["done"] = 1
        elif cmd[0:6] == "proxy:":
            lines = buf.split("\n")
            line = lines.pop(0)
            buf = "\n".join(lines)
            self.parse_hostdata(buf, line.split(':')[1])
        elif cmd == "TLSproxy" or cmd == "HTTPTLSproxy":
            lines = buf.split("\n")
            line = lines.pop(0)
            addr = line.split(" ")[1]
            buf = "\n".join(lines)
            ret = self.handle_net_message(buf, f"TLS proxy for {addr}")
        elif cmd == "client":
            self.parse_hostdata(buf, addr)
        else:
            if len(sbuf) > 1:
                self.debug(f"DEBUG: handle_net_message do not handle {cmd} {sbuf[1]}X")
            else:
                self.debug(f"DEBUG: handle_net_message do not handle {cmd}X")
        return ret

    def set_netport(self, port):
        if port <= 0 or port > 65535:
            return False
        self.netport = port
        return True

    def set_tlsport(self, port):
        if port <= 0 or port > 65535:
            return False
        self.tlsport = port
        return True

    def set_xymonvar(self, p):
        self.xy_data = p
        self.vars["XYMONVAR"] = p

    def init_pika(self):
        self.debug("DEBUG: init pika")
        pika_user = self.xython_getvar("PIKA_USER")
        if pika_user is None:
            self.error("ERROR: did not found PIKA_USER")
            return False
        pika_password = self.xython_getvar("PIKA_PASSWORD")
        if pika_password is None:
            self.error("ERROR: did not found PIKA_PASSWORD")
            return False
        credentials = pika.PlainCredentials(pika_user, pika_password)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host='127.0.0.1', port=5672, credentials=credentials, heartbeat=5
            )
        )
        self.channel = connection.channel()
        self.channel.exchange_declare(exchange='xython-status', exchange_type='fanout')
        self.channel.exchange_declare(exchange='xython-ping', exchange_type='fanout')
        return True

    def init(self):
        global has_pika
        self.has_pika = has_pika
        if self.has_pika:
            if not self.init_pika():
                self.has_pika = False
        ts_start = time.time()
        self.etcdir = self.etcdir.rstrip('/')
        self.load_xymonserver_cfg()
        self.load_client_local_cfg()
        if self.xy_data is None:
            self.xy_data = self.xymon_getvar("XYMONVAR")
        self.histdir = self.xymon_getvar("XYMONHISTDIR")
        self.xy_hostdata = self.xy_data + 'hostdata/'
        self.histlogs = self.xymon_getvar("XYMONHISTLOGS")
        self.serverdir = self.xymon_getvar("XYMONHOME")
        webdir = self.xymon_getvar("XYTHON_WEB")
        if webdir == '':
            self.webdir = self.serverdir + "/web/"
        else:
            self.webdir = webdir
        if self.wwwdir is None:
            self.wwwdir = self.serverdir + "/www/"
        if self.xt_data is None:
            self.xt_data = "/var/lib/xython/"
        # TODO use the XYXXX variables
        self.xt_hostdata = f"{self.xt_data}/hostdata"
        self.xt_histlogs = f"{self.xt_data}/histlogs"
        self.xt_histdir = f"{self.xt_data}/hist/"
        self.xt_rrd = f"{self.xt_data}/rrd/"
        self.xt_acks = f"{self.xt_data}/acks/"
        self.xt_state = f"{self.xt_data}/state/"
        self.xt_inventorydir = f"{self.xt_data}/inventory/"
        if self.xythonmode > 0:
            if not os.path.exists(self.xt_data):
                try:
                    os.mkdir(self.xt_data)
                except:
                    self.error(f"ERROR: fail to create {self.xt_data}")
                    sys.exit(1)
            if not os.path.exists(self.xt_histlogs):
                os.mkdir(self.xt_histlogs)
            if not os.path.exists(self.xt_histdir):
                os.mkdir(self.xt_histdir)
            if not os.path.exists(self.xt_hostdata):
                os.mkdir(self.xt_hostdata)
            if not os.path.exists(self.xt_logdir):
                os.mkdir(self.xt_logdir)
            if not os.path.exists(self.xt_rrd):
                os.mkdir(self.xt_rrd)
            if not os.path.exists(self.xt_acks):
                os.mkdir(self.xt_acks)
            if not os.path.exists(self.xt_state):
                os.mkdir(self.xt_state)
            if not os.path.exists(self.xt_inventorydir):
                os.mkdir(self.xt_inventorydir)
        FileOutputHandler = logging.FileHandler(self.xt_logdir + 'logging.log')
        FileOutputHandler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(FileOutputHandler)
        need_debug = self.xython_getvar('DEBUG')
        if need_debug is not None and need_debug == "1":
            self.enable_debug()
            self.log(self.daemon_name, "ENABLE DEBUG MODE")
        debugs = self.xython_getvar('DEBUGS')
        if debugs:
            self.debugs = debugs.split(',')
            for debug in self.debugs:
                self.log(self.daemon_name, f"Enabling debug for {debug}")
        # TODO get timezone from /etc/timezone ?
        tz = self.xython_getvar('TIMEZONE')
        if tz is not None:
            if tz not in pytz.all_timezones:
                self.error(f"ERROR: Invalid timezone name {tz}")
                sys.exit(1)
            self.tz = tz
            self.debug(f'DEBUG: set timezone to {self.tz}')
        self.db = self.xt_data + '/xython.db'
        self.debug(f"DEBUG: DB is {self.db}")
        print(f"DEBUG: DB === {self.db}")
        # we always restart with a clean DB
        if os.path.exists(self.db):
            os.remove(self.db)
        if self.tls_key is None:
            self.tls_key = self.xython_getvar('XYTHON_TLS_KEY')
        if self.tls_cert is None:
            self.tls_cert = self.xython_getvar('XYTHON_TLS_CRT')
        self.sqconn = sqlite3.connect(self.db)
        self.sqc = self.sqconn.cursor()
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS columns
            (hostname text, column text, ts date, expire date, color text, ackend date, ackcause text, UNIQUE(hostname, column))''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS history
            (hostname text, column text, ts date, duration int, color text, ocolor text)''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS tests
            (hostname text, column text, next date, UNIQUE(hostname, column))''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS pages
            (hostname text NOT NULL, pagename text NOT NULL, groupname TEXT, UNIQUE(hostname, pagename, groupname))''')
        self.sqc.execute('DELETE FROM tests')
        ret = self.read_configs()
        if not ret:
            sys.exit(1)
        self.read_acks()
        try:
            self.sqconn.commit()
        except sqlite3.OperationalError as e:
            self.error(f"ERROR: fail to commit sqlite {self.db} {str(e)}")
            sys.exit(1)
        for column in ['mdstat']:
            cname = self.xython_getvar(f'COLUMN_NAME_{column}')
            if cname is None:
                continue
            if is_valid_column(cname):
                self.debug(f"DEBUG: mdstat column renamed from {self.colnames[column]} to {cname}")
                self.colnames[column] = cname
            else:
                self.error(f"ERROR: COLUMN_NAME_{column} give a bad name {cname}")
        ts_end = time.time()
        self.debug("STAT: init loaded hist in %f" % (ts_end - ts_start))

# read hosts.cfg and analysis.cfg
# check if thoses files need to be reread
    def read_configs(self):
        ret = self.load_rrddefinitions_cfg()
        if ret == self.RET_ERR:
            return False
        self.load_xymonserver_cfg()
        self.load_graphs_cfg()
        # TODO retcode
        self.read_protocols()
        ret = self.read_hosts()
        if ret == self.RET_ERR:
            self.error("ERROR: failed to read hosts")
            return False
        if ret == self.RET_NEW:
            self.hosts_check_tags()
            # if hosts has changed we need to reread analysis
            self.time_read_analysis = 0
        self.read_analysis2()
        for hostname in self.xy_hosts:
            H = self.xy_hosts[hostname]
            if not self.read_hist(H.name):
                self.error(f"ERROR: failed to read hist for {H.name}")
        if ret == self.RET_NEW:
            self.gen_tests()
        return True

    def page_init(self):
        self.pagelist = {}
        self.pagelist['all'] = {}
        self.pagelist['nongreen'] = {}

    def page_add(self, pagename):
        self.debug(f"DEBUG: create page {pagename}")
        if pagename in self.pagelist:
            self.error(f"ERROR: {pagename} already exists")
            return self.RET_ERR
        self.pagelist[pagename] = {}
        return self.RET_NEW

    def page_remove(self, pagename):
        # TODO
        if pagename not in self.pagelist:
            self.error(f"ERROR: {pagename} do not exists")
            return self.RET_ERR

    def host_add_to_page(self, pagename, hostname, group):
        self.debugdev("page", f'DEBUG: add {hostname} to {pagename} (group={group})')
        if pagename not in self.pagelist:
            self.error(f"ERROR: {pagename} do not exists")
            return self.RET_ERR
        self.sqc.execute('INSERT OR REPLACE INTO pages (pagename, hostname, groupname) VALUES (?, ?, ?)', (pagename, hostname, group))

    def host_page_clean(self, hostname):
        self.debug(f"DEBUG: page clean {hostname}")
        self.sqc.execute('DELETE FROM pages WHERE hostname == (?)', [hostname])

    def print(self):
        print(f"VAR is {self.xy_data}")
        print(f"HIST is {self.histdir}")
        print(f"HISTLOGS is {self.histlogs}")
        print(f"XHIST is {self.xt_histdir}")
        print(f"XHOSTDATA is {self.xt_hostdata}")
        print(f"XHISTLOGS is {self.xt_histlogs}")
        print(f"WEB is {self.webdir}")
        print(f"WWW is {self.wwwdir}")
        print(f"DB is {self.db}")
        print(f"LOG is {self.xt_logdir}")

    async def do_scheduler(self):
        while True:
            if self.quit > 0:
                if self.uptime_start + self.quit < time.time():
                    sys.exit(0)
            self.scheduler()
            await asyncio.sleep(1)

    async def handle_unix_client(self, reader, writer):
        data = await reader.read(320000)
        message = data.decode("UTF8")
        ret = self.handle_net_message(message, "unix")
        if "send" in ret:
            writer.write(ret["send"].encode("UTF8"))
        if "bsend" in ret:
            writer.write(ret["bsend"])
        try:
            await writer.drain()
        except BrokenPipeError as e:
            self.error(f"ERROR: handle_unix_client: {str(e)}")
        except ConnectionResetError as e:
            self.error(f"ERROR: handle_unix_client: {str(e)}")
        writer.close()
        return

    async def handle_inet_client(self, reader, writer):
        peername = writer.get_extra_info('peername')
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=10)
        except TimeoutError:
            writer.close()
            return
        message = data.decode("UTF8")
        lsbuf = self.send_client_local(message)
        if lsbuf:
            sbuf = "\n".join(lsbuf)
            writer.write(sbuf.encode("UTF8"))
            await writer.drain()
        while True:
            try:
                data = await asyncio.wait_for(reader.read(320000), timeout=10)
                message += data.decode("UTF8")
                if len(data) == 0:
                    self.handle_net_message(message, peername)
                    writer.close()
                    return
                await writer.drain()
            except TimeoutError:
                writer.close()
                return
            except ConnectionResetError:
                writer.close()
                self.handle_net_message(message, peername)
                return
            except asyncio.exceptions.CancelledError:
                writer.close()
                return

    async def run(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        self.debug(f"DEBUG: resources hard={hard} soft={soft}")
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        self.debug(f"DEBUG: resources after hard={hard} soft={soft}")
        self.tasks = []

        coro = asyncio.start_server(self.handle_inet_client, '0.0.0.0', self.netport, backlog=1000, sock=self.s)
        self.tasks.append(coro)
        if self.ipv6:
            coro = asyncio.start_server(self.handle_inet_client, '::', self.netport, backlog=1000)
            self.tasks.append(coro)
        if self.tls_cert and self.tls_key:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self.tls_cert, self.tls_key)
            self.log(self.daemon_name, "START TLS");
            coro = asyncio.start_server(self.handle_inet_client, '0.0.0.0', self.tlsport, backlog=1000, ssl=ssl_ctx)
            self.tasks.append(coro)
        else:
            self.log(self.daemon_name, f"DO NOT START TLS")
        if os.path.exists(self.unixsock):
            os.unlink(self.unixsock)
        self.us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.us.bind(self.unixsock)
        except FileNotFoundError as e:
            self.error(f"ERROR: fail to bind to {self.unixsock} {str(e)}")
            return
        # TODO does it is necessary ?, check setup with apache
        os.chmod(self.unixsock, 0o666)
        self.us.listen(100)
        coro = asyncio.start_unix_server(self.handle_unix_client, sock=self.us)
        self.tasks.append(coro)
        sc = asyncio.create_task(self.do_scheduler())
        self.tasks.append(sc)
        try:
            await asyncio.gather(*self.tasks)
        except OSError as e:
            self.error(f"DEBUG: catched {str(e)}")
