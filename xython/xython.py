#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import os
import time
import re
import sys
from random import randint
import socket
from importlib.metadata import version
from pathlib import Path
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
from .xython_tests import ping
from .xython_tests import dohttp
from .xython_tests import dossh
import celery
from .common import xytime
from .common import xytime_
from .common import xyts_
from .common import gcolor
from .common import gif
from .common import setcolor
from .common import xydhm
from .common import xydelay
from .common import COLORS

from .rules import xy_rule_disks
from .rules import xy_rule_port
from .rules import xy_rule_proc
from .rules import xy_rule_mem
from .rules import xy_rule_cpu
from .rules import xy_rule_sensors


class xy_host:
    def __init__(self, name):
        self.last_ping = 0
        self.name = name
        self.tests = []
        self.hostip = ""
        self.rules = {}
        self.rhcnt = 0
        self.hist_read = False
        # last time we read analysis
        self.time_read_analysis = 0
        self.rules["DISK"] = None
        self.rules["INODE"] = None
        self.rules["PORT"] = []
        self.rules["PROC"] = []
        self.rules["MEMPHYS"] = None
        self.rules["MEMACT"] = None
        self.rules["MEMSWAP"] = None
        self.rules["CPU"] = None
        self.rules["SENSOR"] = None

    # def debug(self, buf):
    #    if self.edebug:
    #        print(buf)

    def add_test(self, ttype, url, port):
        T = None
        for Tt in self.tests:
            if Tt.type == ttype:
                # self.debug("DEBUG: found test %s" % ttype)
                T = Tt
        if T is None:
            # self.debug(f"DEBUG: create test  {ttype} with URL={url}")
            T = xytest(self.name, ttype, url, port)
            self.tests.append(T)
        else:
            T.add(url)


class xytest:
    def __init__(self, hostname, ttype, url, port):
        self.ts = time.time()
        self.hostname = hostname
        self.next = time.time()
        self.type = ttype
        self.urls = []
        self.urls.append(url)
        self.port = port

    def add(self, url):
        self.urls.append(url)


RET_OK = 0
RET_ERR = 1
RET_NEW = 2
class xythonsrv:
    def __init__(self):
        self.xy_hosts = []
        self.tests = []
        self.xythonmode = 2
        self.uclients = []
        self.clients = []
        self.s = None
        self.us = None
        self.netport = 1984
        self.ipv6 = False
        self.edebug = False
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
        self.ts_page = time.time()
        self.ts_tests = time.time()
        self.ts_check = time.time()
        self.ts_read_configs = time.time()
        self.expires = []
        self.stats = {}
        self.uptime_start = time.time()
        self.etcdir = '/etc/xymon/'
        self.xt_logdir = "/var/log/xython/"
        self.wwwdir = None
        self.xy_data = None
        self.xt_data = None
        self.xt_rrd = None
        self.vars = {}
        self.debugs = []
        self.msgn = 0
        # to be compared with mtime of hosts.cfg
        self.time_read_hosts = 0
        # each time read_hosts is called, read_hosts_cnt is ++ abd all hosts found are set to this value
        # so all hosts with a lower value need to be removed
        self.read_hosts_cnt = 0

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
        res = self.sqc.execute(req)

    # used only at start
    def column_set(self, hostname, cname, color, ts, expire=60):
        color = gcolor(color)
        now = time.time()
        req = f'INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color) VALUES ("{hostname}", "{cname}", {ts}, {now} + {expire}, "{color}")'
        res = self.sqc.execute(req)

    def debug(self, buf):
        if self.debug:
            print(buf)

    def debugdev(self, facility, buf):
        if self.debug and facility in self.debugs:
            print(buf)

    def log(self, facility, buf):
        f = open("%s/%s.log" % (self.xt_logdir, facility), 'a')
        f.write(f"{xytime(time.time())} {buf}\n")
        f.close()

    def error(self, buf):
        print(buf)
        self.log("error", buf)

    # get configuration values from xython
    def xython_getvar(self, varname):
        # TODO handle fail
        f = open(f"{self.etcdir}/xython.cfg", 'r')
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
                #found = sline[1].split('"')[1]
                found = sline[1]
                #self.debug(f"getvar {varname}={found}")
                return found
        self.debugdev('vars', "DEBUG: did not found %s" % varname)
        return None

    def xython_is_ack(self, hostname, column):
        req = f'SELECT ackend, ackcause FROM columns WHERE hostname="{hostname}" AND column="{column}"'
        res = self.sqc.execute(req)
        results = self.sqc.fetchall()
        if len(results) == 0:
            return None
        if results[0][0] == None:
            return None
        return results

    # get variables from /etc/xymon
    def xymon_getvar(self, varname):
        if varname in self.vars:
            return self.vars[varname]
        # TODO handle fail
        f = open(f"{self.etcdir}/xymonserver.cfg", 'r')
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
                found = sline[1].split('"')[1]
                #self.debug(f"getvar {varname}={found}")
                return found
        self.debugdev('vars', "DEBUG: did not found %s" % varname)
        return ""

    def xymon_replace(self, buf):
        #self.debug(f"REPLACE {buf}")
        ireplace = 0
        while ireplace < 10:
            self.debugdev('vars', f"REPLACE {ireplace} {buf}")
            toreplace = re.findall(r"\$[A-Z][A-Z_]*", buf)
            if len(toreplace) == 0:
                return buf
            for xvar in toreplace:
                xvarbase = xvar.replace("$", "")
                self.debugdev('vars', f"XVARBASE=={xvarbase} from {xvar}")
                buf = re.sub(r"\$%s" % xvarbase, self.xymon_getvar(xvarbase), buf)
            ireplace += 1
        return buf

    # TODO template jinja ?
    def gen_html(self, kind, hostname, column, ts):
        now = time.time()
        gcolor = 'green'
        html = ""
        # concat
        fh = open(self.webdir + "/stdnormal_header", "r")
        html += fh.read()
        fh.close()

        if kind == 'nongreen' or kind == 'all':
            # dump hosts
            html += "<center>\n"
            html += '<A NAME=begindata>&nbsp;</A>\n'
            html += '<A NAME="hosts-blk">&nbsp;</A>\n'
            html += '<A NAME=hosts-blk-1>&nbsp;</A>\n'

            html += '<CENTER><TABLE SUMMARY=" Group Block" BORDER=0 CELLPADDING=2>\n'
            html += '<TR><TD VALIGN=MIDDLE ROWSPAN=2><CENTER><FONT COLOR="#FFFFF0" SIZE="+1"></FONT></CENTER></TD>'

            # TODO handle all green column
            if kind == 'nongreen':
                res = self.sqc.execute("SELECT DISTINCT column FROM columns where color != 'green' ORDER BY column")
                # TODO
                gcolor = 'red'
            else:
                res = self.sqc.execute("SELECT DISTINCT column FROM columns ORDER BY column")
            results = self.sqc.fetchall()
            cols = []
            for col in results:
                colname = col[0]
                cols.append(colname)
            # for each column
                html += '<TD ALIGN=CENTER VALIGN=BOTTOM WIDTH=45>\n<A HREF="$XYMONSERVERCGIURL/columndoc.sh?%s"><FONT COLOR="#87a9e5" SIZE="-1"><B>%s</B></FONT></A> </TD>\n' % (colname, colname)
            html += '</TR><TR><TD COLSPAN=%d><HR WIDTH="100%%"></TD></TR>\n' % len(results)

            if kind == 'nongreen':
                res = self.sqc.execute('SELECT DISTINCT hostname FROM columns WHERE hostname IN (SELECT hostname WHERE color != "green") ORDER by ackend, hostname')
            else:
                res = self.sqc.execute('SELECT DISTINCT hostname FROM columns ORDER BY hostname')
            hostlist = self.sqc.fetchall()
            # TODO results up is not used
            for host in hostlist:
                H = self.find_host(host[0])
                if H is None:
                    continue
                # if kind == 'nongreen':
                res = self.sqc.execute('SELECT column,ts,color FROM columns WHERE hostname == "%s"' % H.name)
                #else:
                #    res = self.sqc.execute('SELECT column,ts,color FROM columns WHERE hostname == "%s"' % H.name)
                results = self.sqc.fetchall()
                hcols = {}
                hts = {}
                for col in results:
                    hcols[col[0]] = col[2]
                    hts[col[0]] = col[1]
                html += '<TR class=line>\n'
                html += '<TD NOWRAP ALIGN=LEFT><A NAME="%s">&nbsp;</A>\n' % H.name
                html += '<A HREF="/xython/xython.html" ><FONT SIZE="+1" COLOR="#FFFFCC" FACE="Tahoma, Arial, Helvetica">%s</FONT></A>' % H.name
                for Cname in cols:
                    if Cname not in hcols:
                        html += '<TD ALIGN=CENTER>-</TD>\n'
                    else:
                        html += '<TD ALIGN=CENTER>'
                        lcolor = hcols[Cname]
                        lts = hts[Cname]
                        dhm = xydhm(lts, now)
                        acki = self.xython_is_ack(H.name, Cname)
                        if acki == None or lcolor == 'green':
                            isack = False
                        else:
                            isack = True
                        if self.xythonmode > 0:
                            html += f'<A HREF="$XYMONSERVERCGIURL/xythoncgi.py?HOST=%s&amp;SERVICE=%s"><IMG SRC="/xython/gifs/%s" ALT="%s:%s:{dhm}" TITLE="%s:%s:{dhm}" HEIGHT="16" WIDTH="16" BORDER=0></A></TD>' % (H.name, Cname, gif(lcolor, lts, isack), Cname, lcolor, Cname, lcolor)
                        else:
                            html += f'<A HREF="$XYMONSERVERCGIURL/svcstatus.sh?HOST=%s&amp;SERVICE=%s"><IMG SRC="/xymon/gifs/%s" ALT="%s:%s:{dhm}" TITLE="%s:%s:{dhm}" HEIGHT="16" WIDTH="16" BORDER=0></A></TD>' % (H.name, Cname, gif(lcolor, lts, isack), Cname, lcolor, Cname, lcolor)
                html += '</TR>\n'

            html += '</TABLE></CENTER><BR>'

        history_extra = ""
        if kind == 'svcstatus':
            rdata = self.get_histlogs(hostname, column, ts)
            if rdata is None:
                html = "HIST not found"
                return html
            gcolor = rdata["first"]
            html += '<CENTER><TABLE ALIGN=CENTER BORDER=0 SUMMARY="Detail Status">'
            # TODO replace with first line of status (without color)
            html += '<TR><TD ALIGN=LEFT><H3>%s</H3>' % rdata["first"]
            html += '<PRE>'
            data = ''.join(rdata["data"])
            data.replace("\n", '<br>')
            data = re.sub("\n", '<br>', data)
            for gifc in COLORS:
                data = re.sub("&%s" % gifc, '<IMG SRC="$XYMONSERVERWWWURL/gifs/%s.gif">' % gifc, data)
            html += data
            html += '</PRE>\n</TD></TR></TABLE>'
            html += '<br><br>\n'
            html += '<table align="center" border=0 summary="Status report info">'
            html += f'<tr><td align="center"><font COLOR="#87a9e5" SIZE="-1">Status unchanged in {xydhm(ts, now)}<br>'
            html += 'Status %s<br>' % rdata["sender"]
            if self.xythonmode > 0:
                html += '<a href="$XYMONSERVERCGIURL/xythoncgi.py?CLIENT={hostname}">Client data</a> available<br>'
            else:
                html += '<a href="$XYMONSERVERCGIURL/svcstatus.sh?CLIENT={hostname}">Client data</a> available<br>'
            html += '</font></td></tr>\n</table>\n</CENTER>\n<BR><BR>\n'
            history_extra = f'AND hostname="{hostname}" AND column="{column}"'

            res = self.sqc.execute(f'SELECT ackend, ackcause FROM columns WHERE hostname == "{hostname}" and column == "{column}"')
            ackinfos = self.sqc.fetchall()
            if len(ackinfos) == 1:
                print(ackinfos)
                ackinfo = ackinfos[0]
                ackend = ackinfo[0]
                if ackend is not None:
                    ackmsg = ackinfo[1]
                    html += f'<CENTER>Current acknowledgement: {ackmsg}<br>Next update at: {xytime(int(ackend))}</CENTER>\n'
            else:
                print(f"ackinfo is len={len(ackinfo)}")
            # TODO acknowledge is only for non-history and non-green
            html += f'<CENTER>\n<form action="$XYMONSERVERCGIURL/xythoncgi.py" method="post">\n'
            html += '<input type="text" placeholder="61" SIZE=6 name="duration" required>\n'
            html += '<input type="text" name="cause" required>\n'
            html += f'<input type="hidden" name="hostname" value="{hostname}">\n'
            html += f'<input type="hidden" name="service" value="{column}">\n'
            html += f'<input type="hidden" name="returnurl" value="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hostname}&amp;SERVICE={column}">\n'
            html += '<button type="submit">Send</button></form>\n'
            html += '</CENTER>\n'

            if has_rrdtool:
                if column in ['disk', 'inode', 'sensor']:
                    html += f'<CENTER><img src="/xython/{hostname}/{column}.png"></CENTER>'


        # history
        res = self.sqc.execute(f"SELECT * FROM history WHERE ts > {now} - 240 *60 {history_extra} ORDER BY ts DESC LIMIT 100")
        results = self.sqc.fetchall()
        hcount = len(results)
        if hcount > 0:
            lastevent = results[hcount - 1]
            minutes = (now - lastevent[2]) // 60 + 1
        else:
            minutes = 0
        html += '<center>'
        html += '<TABLE SUMMARY="$EVENTSTITLE" BORDER=0>\n<TR BGCOLOR="#333333">'
        # TODO minutes
        html += f'<TD ALIGN=CENTER COLSPAN=6><FONT SIZE=-1 COLOR="#33ebf4">{hcount}&nbsp;events&nbsp;received&nbsp;in&nbsp;the&nbsp;past&nbsp;{minutes}&nbsp;minutes</FONT></TD></TR>\n'
        for change in results:
            hhostname = change[0]
            hcol = change[1]
            hts = change[2]
            hduration = change[3]
            hcolor = change[4]
            hocolor = change[5]
            html += '<TR BGCOLOR=#000000>'
            html += '<TD ALIGN=CENTER>%s</TD>' % xytime(hts)
            html += '<TD ALIGN=CENTER BGCOLOR=%s><FONT COLOR=black>%s</FONT></TD>' % (hcolor, hhostname)
            html += '<TD ALIGN=LEFT>%s</TD>' % hcol
            html += f'<TD><A HREF="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hhostname}&amp;SERVICE={hcol}&amp;TIMEBUF={xytime_(hts - hduration)}">'
            html += f'<IMG SRC="$XYMONSERVERWWWURL/gifs/{gif(hocolor, hts)}"  HEIGHT="16" WIDTH="16" BORDER=0 ALT="{hocolor}" TITLE="{hocolor}"></A>'
            html += '<IMG SRC="$XYMONSERVERWWWURL/gifs/arrow.gif" BORDER=0 ALT="From -&gt; To">'
            html += f'<TD><A HREF="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hhostname}&amp;SERVICE={hcol}&amp;TIMEBUF={xytime_(hts)}">'
            html += f'<IMG SRC="$XYMONSERVERWWWURL/gifs/{gif(hcolor, hts)}"  HEIGHT="16" WIDTH="16" BORDER=0 ALT="{hcolor}" TITLE="{hcolor}"></A>'
            html += '</TR>'
        html += '</center>'

        fh = open(self.webdir + "/stdnormal_footer", "r")
        html += fh.read()
        fh.close()

        fh = open(self.etcdir + "/xymonmenu.cfg")
        body_header = fh.read()
        fh.close()
        html = re.sub("&XYMONBODYHEADER", body_header, html)
        html = re.sub("&XYMONBODYFOOTER", "", html)
        html = re.sub("&XYMONDREL", f'{version("xython")}', html)
        html = re.sub("&XYMWEBREFRESH", "60", html)
        html = re.sub("&XYMWEBBACKGROUND", gcolor, html)
        html = re.sub("&XYMWEBDATE", xytime(time.time()), html)
        html = re.sub("&HTMLCONTENTTYPE", self.xymon_getvar("HTMLCONTENTTYPE"), html)
        # find remaining variables
        ireplace = 0
        while ireplace < 20:
            toreplace = re.findall(r"\&XY[A-Z][A-Z]*", html)
            for xvar in toreplace:
                xvarbase = xvar.replace("&", "")
                html = re.sub(xvar, self.xymon_getvar(xvarbase), html)
            toreplace = re.findall(r"\$XY[A-Z][A-Z]*", html)
            for xvar in toreplace:
                xvarbase = xvar.replace("$", "")
                html = re.sub(r"\$%s" % xvarbase, self.xymon_getvar(xvarbase), html)
            ireplace += 1

        if kind == 'nongreen':
            fhtml = open(self.wwwdir + '/nongreen.html', 'w')
            fhtml.write(html)
            fhtml.close()
            # TODO find a better solution
            os.chmod(self.wwwdir + "/nongreen.html", 0o644)
            return
        if kind == 'all':
            fhtml = open(self.wwwdir + '/xython.html', 'w')
            fhtml.write(html)
            fhtml.close()
            # TODO find a better solution
            os.chmod(self.wwwdir + "/xython.html", 0o644)
            return
        return html

    def dump(self, hostname):
        print("======= DUMP HOST %s" % hostname)
        H = self.find_host(hostname)
        if H is None:
            return
        req = f'SELECT * FROM columns WHERE hostname == "{hostname}"'
        res = self.sqc.execute(req)
        results = self.sqc.fetchall()
        for sqr in results:
            print(f'{sqr[1]} {sqr[4]} TS={sqr[2]}')
        for T in H.tests:
            for url in T.urls:
                print("\tTEST: %s %s" % (T.type, url))
        print(H.rules)

# read hosts.cfg
# return RET_OK if nothing new was read
# return RET_ERR on error
# return RET_NEW if hosts.cfg was read
    def read_hosts(self):
        mtime = os.path.getmtime(self.etcdir + "/hosts.cfg")
        self.debug(f"DEBUG: compare mtime={mtime} and time_read_hosts={self.time_read_hosts}")
        if self.time_read_hosts < mtime:
            self.time_read_hosts = mtime
        else:
            return RET_OK
        self.debug(f"DEBUG: read_hosts in {self.etcdir}")
        self.read_hosts_cnt += 1
        try:
            fhosts = open(self.etcdir + "/hosts.cfg", 'r')
        except:
            self.error("ERROR: cannot open hosts.cfg")
            return RET_ERR
        for line in fhosts:
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
            host_ip = sline.pop(0)
            host_name = sline.pop(0)
            self.debug("DEBUG: ip=%s host=%s" % (host_ip, host_name))
            # conn is enabled by default
            need_conn = True
            H = self.find_host(host_name)
            if H is not None:
                self.xy_hosts.remove(H)
            H = xy_host(host_name)
            H.rhcnt = self.read_hosts_cnt
            H.hostip = host_ip
            while len(sline) > 0:
                test = sline.pop(0)
                if len(test) == 0:
                    continue
                if test == '#':
                    continue
                if test[0] == '#':
                    test = test[1:]
                if test[0:6] == 'noconn':
                    need_conn = False
                if test[0:4] == 'conn':
                    H.add_test("conn", test, None)
                    need_conn = False
                elif test[0:3] == 'ssh':
                    #self.debug(f"\tDEBUG: ssh tests {test}")
                    port = 22
                    remain = test[3:]
                    if len(remain) > 0:
                        self.debug(f"REMAIN: {remain}")
                        if remain[0] != ':':
                            self.error(f"Config error, missing : at {sline}")
                            return RET_ERR
                        words = remain.split(":")
                        port = int(words[1])
                    H.add_test("ssh", test, port)
                elif test[0:4] == 'http':
                    self.debug("\tDEBUG: HTTP tests %s" % test)
                    H.add_test("http", test, None)
                else:
                    self.log("todo", f"TODO hosts: test={test}")
                    self.debug(f"\tDEBUG: test={test}xxx")
            if need_conn:
                H.add_test("conn", test, None)
            self.xy_hosts.append(H)
        for H in self.xy_hosts:
            if H.rhcnt < self.read_hosts_cnt:
                self.debug(f"DEBUG: read_hosts: purge {H.name}")
                self.xy_hosts.remove(H)
        return RET_NEW

    def find_host(self, hostname):
        for H in self.xy_hosts:
            if H.name == hostname:
                return H
        return None

    def save_hostdata(self, hostname, buf, ts):
        if self.readonly:
            return
        hdir = "%s/%s" % (self.xt_hostdata, hostname)
        if not os.path.exists(hdir):
            os.mkdir(hdir)
        hfile = "%s/%d" % (hdir, ts)
        f = open(hfile, 'w')
        f.write(buf)
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

    # return all cname for a host in a list
    def get_columns(self, hostname):
        print(f"DEBUG: get_columns {hostname}")
        res = self.sqc.execute(f'SELECT column FROM columns WHERE hostname == "{hostname}"')
        results = self.sqc.fetchall()
        if len(results) >= 1:
            allc = []
            for r in results:
                allc.append(r[0])
            return allc
        return None

    def get_column_state(self, hostname, cname):
        res = self.sqc.execute('SELECT * FROM columns WHERE hostname == ? AND column == ?', (hostname, cname))
        results = self.sqc.fetchall()
        if len(results) == 1:
            return results[0]
        return None

    def column_update(self, hostname, cname, color, ts, data, expire, updater):
        color = gcolor(color)
        ts_start = time.time()
        expiretime = ts_start + expire
        H = self.find_host(hostname)
        if not H:
            #self.debug("DEBUG: %s not exists" % hostname)
            # TODO autoregister
            H = xy_host(hostname)
            H.hostip = hostname
            self.xy_hosts.append(H)
        ackend = None
        acktime = None
        ackcause = None
        ocolor = "-"
        ots = ts
        res = self.sqc.execute('SELECT * FROM columns WHERE hostname == ? AND column == ?', (hostname, cname))
        results = self.sqc.fetchall()
        if len(results) > 1:
            self.error("ERROR: this is impossible")
            return
        if len(results) == 0:
            if color == 'purple':
                self.error("ERROR: creating a purple column")
                return
            #self.debug("DEBUG: create column %s on %s" % (cname, hostname))
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
            self.debug(f"DEBUG: BLUE {cname} expire={expiretime} {xytime(expiretime)} oexpire={result[3]} {xytime(result[3])}")
            expiretime = result[3]
            # get reason
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                self.error("ERROR: keeping blue without status")
                return
            odata = ''.join(rdata["raw"])
            lodata = odata.split("\n\n")
            firsts = lodata[0].split(" ", 1)[1]
            # remove the first colour
            blue_header = firsts + "\n\n" + lodata[1] + "\n\n"
            data = blue_header + data
        if color == 'purple':
            if ocolor == 'purple':
                self.error("ERROR: cannot go from purple to purple")
                return
        #self.debug("%s %s color=%s ocolor=%s ts=%s ots=%s" % (hostname, cname, ocolor, color, ts, ots))
        if color == ocolor:
            ts = ots
        else:
            duration = ts - ots
            self.save_hist(hostname, cname, color, ocolor, ts, ots, duration)
            self.history_update(hostname, cname, ts, duration, color, ocolor)
        if color == 'purple':
            if data is not None:
                print("ERROR")
            #duplicate
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                self.error("ERROR: cannot purple without status")
                return
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
            status = f"@@status#{self.msgn}/{hostname}|{ts}|{updater}||{hostname}|{cname}|{ts}|{color}||{ocolor}|{ts}|{acktime}|{ackmsg}|0||{ts}|linux||0|\n"
            status += data
            status += '\n@@'
            self.msgn += 1
            properties = pika.BasicProperties(expiration=str(10000))
            self.channel.basic_publish(exchange='xython-status', routing_key='', body=status, properties=properties)

        #req = f'INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color) VALUES ("{hostname}", "{cname}", {ts}, {ts} + {expire}, "{color}")'
        now = time.time()
        res = self.sqc.execute('INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color, ackend, ackcause) VALUES (?, ?, ?, ?, ?, ?, ?)', (hostname, cname, ts, expiretime, color, ackend, ackcause))
        #self.sqconn.commit()
        if color == 'purple':
            #duplicate
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                return
            data = ''.join(rdata["data"])
        self.save_histlogs(hostname, cname, data, ts, color, updater)
        ts_end = time.time()
        self.stat("COLUPDATE", ts_end - ts_start)

    def get_histlogs(self, hostname, column, ts):
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
            self.error("ERROR: get_histlogs: histlog is too small")
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
        f = open(hfile, 'w')
        f.write("%s " % color)
        f.write(buf)
        # TODO calcul
        f.write("status unchanged in 0.00 minutes\n")
        # TODO get IP
        f.write(f"Message received from {updater}\n")
        # TODO what is the purpose of this ?
        f.write(f"Client data ID {int(ts)}\n")
        f.close()

    # read hist of a host, creating columns
    # this permit to detect current blue
    # a dropped column is detecte by checking existence of host.col files BUT on my system some
    # column has host.col and are still detected as droped by xymon, how it achieves this ?
    # we could speed up reading by only checking last line of host.col BUT I want to validate
    # that I perfectly understood format of all file
    def read_hist(self, name):
        H = self.find_host(name)
        if H is None:
            self.error(f"ERROR: read_hist: {name} not found")
            return False
        if H.hist_read:
            return True
        self.debug(f"DEBUG: read_hist {name}")
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
                #self.debug(f"DEBUG: ignore dropped {name} {column}")
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
            # check color, if blue read histlogs
            if st_new == 'blue' or st_new == 'bl':
                self.debug(f"DEBUG: BLUE CASE {sline}")
                print(xytime(int(tsa)))
                bbuf = self.get_histlogs(H.name, column, tsa)
                print(xytime(int(tsb)))
                bbuf = self.get_histlogs(H.name, column, tsb)
                #print(bbuf)
            self.debugdev("hist", "DEBUG: %s goes from %s to %s" % (column, st_old, st_new))
            if self.readonly:
                self.column_update(H.name, column, st_new, int(tsb), None, 3 * 60, "xython")
            else:
                self.column_set(H.name, column, st_new, tsb)
        for column in hostcols:
            if not hostcols[column]:
                self.error(f"ERROR: remains of {name} {column}")
        return True

    def check_acks(self):
        now = time.time()
        req = f'UPDATE columns SET ackend = null WHERE ackend <= {now}'
        self.sqc.execute(req)

    def acks_dump(self):
        req = f"SELECT hostname, column, ackend, ackcause FROM columns"
        res = self.sqc.execute(req)
        results = self.sqc.fetchall()
        #for col in results:

    def check_purples(self):
        now = time.time()
        ts_start = now
        req = f'SELECT * FROM columns WHERE expire < {now} AND color != "purple"'
        res = self.sqc.execute(req)
        results = self.sqc.fetchall()
        for col in results:
            expire = col[3]
            pdate = xytime(col[2])
            pedate = xytime(expire)
            pnow = xytime(now)
            self.debug("DEBUG: purplelize %s %s %d<%d %s %s < %s" % (col[0], col[1], col[3], now, pdate, pedate, pnow))
            self.column_update(col[0], col[1], "purple", time.time(), None, 0, "xythond")
        ts_end = time.time()
        self.stat("PURPLE", ts_end - ts_start)
        return

    # gen all tests to be scheduled
    def gen_tests(self):
        now = time.time()
        self.debug("DEBUG: GEN TESTS")
        self.sqc.execute('DELETE FROM tests')
        for H in self.xy_hosts:
            for T in H.tests:
                self.debug("DEBUG: %s %s\n" % (H.name, T.type))
                # self.debug(T.urls)
                tnext = now + randint(1, 30)
                res = self.sqc.execute(f'INSERT OR REPLACE INTO tests(hostname, column, next) VALUES ("{H.name}", "{T.type}", {tnext})')

    def dump_tests(self):
        for T in self.tests:
            print("%s %d" % (T.name, int(T.ts)))

    def dohttp(self, T):
        name = f"{T.hostname}_http"
        ctask = dohttp.delay(T.hostname, T.urls)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def doping(self, T):
        H = self.find_host(T.hostname)
        hostip = H.hostip
        name = f"{T.hostname}_conn"
        self.debug(f"DEBUG: doping for {name}")
        if name in self.celerytasks:
            self.error(f"ERROR: lagging test for {name}")
            return False
        ctask = ping.delay(T.hostname, H.hostip)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)
        return True

    def do_ssh(self, T):
        name = f"{T.hostname}_ssh"
        ctask = dossh.delay(T.hostname, T.port)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def do_tests(self):
        self.celery_workers = celery.current_app.control.inspect().ping()
        if self.celery_workers is None:
            self.error("ERROR: no celery workers")
            return
        ts_start = time.time()
        now = time.time()
        res = self.sqc.execute(f'SELECT * FROM tests WHERE next < {now}')
        results = self.sqc.fetchall()
        self.log("tests", f"DEBUG: DO TESTS {len(results)}")
        if len(results) == 0:
            return
        lag = 0
        for test in results:
            hostname = test[0]
            ttype = test[1]
            H = self.find_host(hostname)
            for T in H.tests:
                if T.type == ttype:
                    if T.type == 'conn':
                        if not self.doping(T):
                            lag += 1
                    if T.type == 'http':
                        self.dohttp(T)
                    if T.type == 'ssh':
                        self.do_ssh(T)
        res = self.sqc.execute(f'UPDATE tests SET next = {now} + 120 WHERE next < {now}')
        ts_end = time.time()
        self.stat("tests", ts_end - ts_start)
        self.stat("tests-lag", lag)
        # RIP celery tasks
        now = time.time()
        for ctask in self.celtasks:
            if ctask.ready():
                status = ctask.status
                if status == 'FAILURE':
                    self.celtasks.remove(ctask)
                    self.error("ERROR: celery task error")
                    # TODO better handle this problem, easy to generate by removing ping
                    continue
                ret = ctask.get()
                self.debug(f'DEBUG: result for {ret["hostname"]} {ret["type"]}')
                self.column_update(ret["hostname"], ret["type"], ret["color"], time.time(), ret["txt"], 180, "xython-tests")
                self.celtasks.remove(ctask)
                name = f'{ret["hostname"]}_{ret["type"]}'
                if name not in self.celerytasks:
                    self.error(f"ERROR: BUG {name} not found")
                else:
                    del(self.celerytasks[name])
        ts_end = time.time()
        self.stat("tests-rip", ts_end - ts_start)
        self.stat("tests-remains", len(self.celtasks))
        return

    # TODO hardcoded hostname
    def do_xythond(self):
        now = time.time()
        buf = f"{xytime(now)} - xythond\n"
        for stat in self.stats:
            color = '&clear'
            moy = round(self.stats[stat]["cumul"] / self.stats[stat]["count"],4)
            smin = round(self.stats[stat]["min"],4)
            smax = round(self.stats[stat]["max"],4)
            cur = round(self.stats[stat]["last"],4)
            if stat == 'tests-lag' and cur > 0:
                color = '&yellow'
            buf += f'{color} {stat:13} CURRENT={cur:10} COUNT={self.stats[stat]["count"]:10} MOY={moy:8} MIN={smin:8} MAX={smax:8}\n'
        uptime = now - self.uptime_start
        uptimem = int(uptime/60)
        if uptimem < 1:
            uptimem = 1
        buf += f"Up since {xytime(self.uptime_start)} ({xydhm(self.uptime_start, now)})\n"
        if "COLUPDATE" in self.stats:
            if "count" in self.stats["COLUPDATE"]:
                buf += f'UPDATE/m: {int(self.stats["COLUPDATE"]["count"]/uptimem)}\n'
        #for worker in self.celery_workers:
        #    print(worker)
        res = self.sqc.execute(f'SELECT count(DISTINCT hostname) FROM columns')
        results = self.sqc.fetchall()
        buf += f"Hosts: {results[0][0]}\n"
        res = self.sqc.execute('SELECT count(next) FROM tests')
        results = self.sqc.fetchall()
        buf += f"Active tests: {results[0][0]}\n"
        self.column_update(socket.gethostname(), "xythond", "green", time.time(), buf, 1600, "xythond")

    def scheduler(self):
        #self.debug("====================")
        now = time.time()
        if now > self.ts_tests + 5:
            self.do_tests()
            self.ts_tests = now
            self.gen_rrds()
        if now > self.ts_check + 1:
            self.check_purples()
            self.check_acks()
            self.ts_check = now
        if now > self.ts_page + 30:
            xythond_start = time.time()
            self.do_xythond()
            self.stat("xythond", time.time() - xythond_start)

            ts_start = time.time()
            self.gen_html("nongreen", None, None, None)
            self.gen_html("all", None, None, None)
            ts_end = time.time()
            self.stat("HTML", ts_end - ts_start)
            self.ts_page = now
        if now > self.ts_read_configs + 60:
            self.read_configs()
            self.ts_read_configs = now
        if self.has_pika:
            self.channel.basic_publish(exchange='xython-ping', routing_key='', body="PING")
        self.stat("SCHEDULER", time.time() - now)

    # read analysis.cfg
    def read_analysis(self, hostname):
        H = self.find_host(hostname)
        mtime = os.path.getmtime(f"{self.etcdir}/analysis.cfg")
        #self.debug(f"DEBUG: read_analysis: compare mtime={mtime} and {H.time_read_analysis}")
        if H.time_read_analysis < mtime:
            H.time_read_analysis = mtime
        else:
            return RET_OK
        f = open(f"{self.etcdir}/analysis.cfg", 'r')
        currhost = None
        self.rules = {}
        self.rules["DISK"] = xy_rule_disks()
        self.rules["INODE"] = xy_rule_disks()
        self.rules["PORT"] = []
        self.rules["PROC"] = []
        self.rules["MEMPHYS"] = None
        self.rules["MEMACT"] = None
        self.rules["MEMSWAP"] = None
        self.rules["CPU"] = None
        self.rules["SENSOR"] = None
        for line in f:
            line = line.rstrip()
            line = re.sub(r"\s+", " ", line)
            line = re.sub(r"^\s+", "", line)
            if len(line) == 0:
                continue
            if line[0] == '#':
                continue
            if line[0:4] == 'HOST':
                currhost = line[5:]
                continue
            if line[0:7] == 'DEFAULT':
                currhost = "DEFAULT"
                continue
            memoryrule = None
            if line[0:7] == 'MEMSWAP':
                memoryrule = 'MEMSWAP'
                remain = line[8:]
            if line[0:6] == 'MEMACT':
                memoryrule = 'MEMACT'
                remain = line[7:]
            if line[0:7] == 'MEMPHYS':
                memoryrule = 'MEMPHYS'
                remain = line[8:]
            if memoryrule is not None:
                rm = xy_rule_mem()
                rm.init_from(remain)
                if currhost == 'DEFAULT':
                    self.rules[memoryrule] = rm
                else:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    H.rules[memoryrule] = rm
            elif line[0:4] == 'LOAD' or line[0:2] == 'UP':
                if self.rules["CPU"] is None:
                    rc = xy_rule_cpu()
                else:
                    rc = self.rules["CPU"]
                if currhost == 'DEFAULT':
                    rc.init_from(line)
                    self.rules["CPU"] = rc
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    if H.rules["CPU"] is None:
                        rc = xy_rule_cpu()
                    else:
                        rc = H.rules["CPU"]
                    rc.init_from(line)
                    H.rules["CPU"] = rc
            elif line[0:4] == 'PORT':
                rp = xy_rule_port()
                rp.init_from(line[5:])
                if currhost == 'DEFAULT':
                    self.rules["PORT"].append(rp)
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    H.rules["PORT"].append(rp)
            elif line[0:4] == 'PROC':
                rp = xy_rule_proc()
                rp.init_from(line[5:])
                if currhost == 'DEFAULT':
                    self.rules["PROC"].append(rp)
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    H.rules["PROC"].append(rp)
            elif line[0:4] == 'DISK':
                if currhost == 'DEFAULT':
                    rxd = self.rules["DISK"]
                    rxd.add(line[5:])
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    if H.rules["DISK"] is None:
                        H.rules["DISK"] = xy_rule_disks()
                    rxd = H.rules["DISK"]
                    rxd.add(line[5:])
            elif line[0:5] == 'INODE':
                if currhost == 'DEFAULT':
                    rxd = self.rules["INODE"]
                    rxd.add(line[6:])
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    if H.rules["INODE"] is None:
                        H.rules["INODE"] = xy_rule_disks()
                    rxd = H.rules["INODE"]
                    rxd.add(line[6:])
            elif line[0:6] == 'SENSOR':
                self.debug(f"DEBUG: {line}")
                if currhost == 'DEFAULT':
                    # TODO
                    self.rules["SENSOR"].add(line[7:])
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return RET_ERR
                    if H.rules["SENSOR"] is None:
                        H.rules["SENSOR"] = xy_rule_sensors()
                    H.rules["SENSOR"].add(line[7:])
            else:
                self.log("todo", line)
        # add default rules for DISK/INODE
        self.rules["DISK"].add('%.* 90 95')
        self.rules["INODE"].add('%.* 70 90')
        if self.rules["CPU"] is None:
            self.rules["CPU"] = xy_rule_cpu()
        if self.rules["MEMPHYS"] is None:
            self.rules["MEMPHYS"] = xy_rule_mem()
            self.rules["MEMPHYS"].init_from("100 101")
        if self.rules["MEMACT"] is None:
            self.rules["MEMACT"] = xy_rule_mem()
            self.rules["MEMACT"].init_from("90 97")
        if self.rules["MEMSWAP"] is None:
            self.rules["MEMSWAP"] = xy_rule_mem()
            self.rules["MEMSWAP"].init_from("50 80")
        if self.rules["SENSOR"] is None:
            self.rules["SENSOR"] = xy_rule_sensors()
        self.rules["SENSOR"].add("DEFAULT C 50 60 10 0")
        return RET_NEW

    def rrd_pathname(self, path):
        if path == '/':
            return ',root'
        return path.replace('/', ',').replace(' ', '_')

    def rrd_label(self, path, column):
        if path == f'{column},root':
            return '/'
        return path.replace(column, '').replace(',', '/').replace('.rrd', '')

    def gen_rrds(self):
        if not has_rrdtool:
            return True
        #self.debug("GEN RRDS")
        hosts = os.listdir(f"{self.xt_rrd}")
        for hostname in hosts:
            for column in ["disk", 'inode', 'sensor']:
                self.gen_rrd(hostname, column)

    def get_ds_name(self, l):
        r = []
        for k in l.keys():
            if len(k) > 4:
                if k[-4:] == 'type':
                    ds = k.split('[')[1].split(']')[0]
                    r.append(ds)
        return r


    def gen_rrd(self, hostname, column):
        #self.debug(f"DEBUG: scan RRD for {hostname} for {column}")
        if column == 'sensor':
            rrds = list(Path(f"{self.xt_rrd}/{hostname}/sensor").rglob("*.rrd"))
        else:
            rrds = list(Path(f"{self.xt_rrd}/{hostname}/").rglob(f"{column}*.rrd"))
        #rrds = [f for f in os.listdir(f"{self.xt_rrd}/{hostname}") if re.match(r'%s.*\.rrd' % column, f)]
        if len(rrds) == 0:
            return
        rrds.sort()
        pngpath = f"{self.wwwdir}/{hostname}/{column}.png"
        base = [pngpath,
            f'--title={column} on {hostname}',
            '--width=576', '--height=140',
            '--vertical-label="% Full"',
            '--start=end-4h'
            ]
        i = 0
        sensor_adapter = None
        for rrd in rrds:
            fname = str(os.path.basename(rrd)).replace(".rrd", "")
            rrdfpath = f"{self.xt_rrd}/{hostname}/{rrd}"
            rrdfpath = str(rrd)
            label = self.rrd_label(fname, column)
            info = rrdtool.info(rrdfpath)
            adapter = os.path.dirname(rrd).split('/')[-1]
            for dsname in self.get_ds_name(info):
                if column == 'sensor':
                    label = dsname
                label = label.ljust(20)
                i += 1
                if i == 1:
                    color = '#0000FF'
                elif i == 2:
                    color = '#FF0000'
                elif i == 3:
                    color = '#00FF00'
                elif i == 4:
                    color = '#F0F000'
                else:
                    color = '#F000F0'
                #self.debug(f"DEBUG add DS{i} {dsname} for {label}")
                base.append(f'DEF:pct{i}={rrdfpath}:{dsname}:AVERAGE')
                base.append(f'LINE1:pct{i}{color}')
                if column == 'sensor' and sensor_adapter != adapter:
                    sensor_adapter = adapter
                    base.append(f'COMMENT:{adapter}\\n')
                base.append(f'GPRINT:pct{i}:LAST:{label} \: %5.1lf (cur)')
                base.append(f'GPRINT:pct{i}:MIN: \: %5.1lf (min)')
                base.append(f'GPRINT:pct{i}:MAX: \: %5.1lf (max)')
                base.append(f'GPRINT:pct{i}:AVERAGE: \: %5.1lf (avg)\l')
        rrdup = xytime(time.time()).replace(':', '\\:')
        base.append(f'COMMENT:Updated\: {rrdup}')
        rrdtool.graph(base)
        os.chmod(pngpath, 0o644)

    def do_rrd(self, hostname, rrdname, ds, value):
        #self.debug(f"DEBUG: do_rrd for {hostname} {rrdname} {ds} {value}")
        if not has_rrdtool:
            return
        fname = f"{rrdname}{self.rrd_pathname(ds)}"
        rrdpath = f"{self.xt_rrd}/{hostname}"
        if not os.path.exists(rrdpath):
            os.mkdir(rrdpath)
        rrdfpath = f"{self.xt_rrd}/{hostname}/{fname}.rrd"
        if not os.path.exists(rrdfpath):
            rrdtool.create(rrdfpath, "--start", "now", "--step", "60",
                "RRA:AVERAGE:0.5:1:1200",
                "DS:pct:GAUGE:600:0:100")
        rrdtool.update(rrdfpath, f"N:{value}")

    def do_sensor_rrd(self, hostname, adapter, sname, value):
        #self.debug(f"DEBUG: do_sensor_rrd for {hostname} {adapter} {sname} {value}")
        if not has_rrdtool:
            return
        fname = f"sensor{self.rrd_pathname(sname)}"
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
        dsname = sname.replace(" ", '_')
        if not os.path.exists(rrdfpath):
            rrdtool.create(rrdfpath, "--start", "now", "--step", "60",
                "RRA:AVERAGE:0.5:1:1200",
                f"DS:{dsname}:GAUGE:600:-280:5000")
        else:
            info = rrdtool.info(rrdfpath)
            allds = self.get_ds_name(info)
            #print(f"DEBUG: already exists with {allds} we have {dsname}")
            if dsname not in allds:
                rrdtool.tune(rrdfpath, f"DS:{dsname}:GAUGE:600:-280:5000")
        rrdtool.update(rrdfpath, f'-t{dsname}', f"N:{value}")

    def parse_free(self, hostname, buf, sender):
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_free: host is None for {hostname}")
            return False
        now = time.time()
        # TODO handle other OS case
        color = 'green'
        sbuf = f"{xytime(now)} - Memory OK\n"
        sbuf += "          Memory        Used       Total      Percentage\n"

        for memtype in ["MEMPHYS", "MEMACT", "MEMSWAP"]:
            if H.rules[memtype] is not None:
                ret = H.rules[memtype].memcheck(buf, memtype)
            elif self.rules[memtype] is not None:
                ret = self.rules[memtype].memcheck(buf, memtype)
            sbuf += ret["txt"]
            color = setcolor(ret["color"], color)

        sbuf += buf
        self.column_update(hostname, "memory", color, time.time(), sbuf, 4 * 60, sender)
        self.stat("PARSEFREE", time.time() - now)
        return True

    # TODO Machine has been up more than 0 days
    def parse_uptime(self, hostname, buf, sender):
        now = time.time()
        color = 'green'
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_uptime: host is None for {hostname}")
            return
        udisplay = re.sub(r"^.*up ", "up", buf)
        sbuf = f"{xytime(now)} {udisplay}\n"
        # Check with global rules
        gret = self.rules["CPU"].cpucheck(buf)
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
        self.column_update(hostname, "cpu", color, time.time(), sbuf, 4 * 60, sender)

    def parse_ps(self, hostname, buf, sender):
        now = time.time()
        color = 'green'
        sbuf = f"{xytime(now)} - procs Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_ps: host is None for {hostname}")
            return
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
        self.stat("parseps", ts_end - now)
        self.column_update(hostname, "procs", color, time.time(), sbuf, 4 * 60, sender)

    #TODO
    def parse_ports(self, hostname, buf, sender):
        now = time.time()
        color = 'clear'
        sbuf = f"{xytime(now)} - ports Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_ports: host is None for {hostname}")
            return
        sline = buf.split("\n")
        for port in self.rules["PORT"]:
            ret = port.check(sline)
            sbuf += ret["txt"] + '\n'
            color = setcolor(ret["color"], color)
        for port in H.rules["PORT"]:
            ret = port.check(sline)
            sbuf += ret["txt"] + '\n'
            color = setcolor(ret["color"], color)
        sbuf += buf
        self.column_update(hostname, "ports", color, time.time(), sbuf, 4 * 60, sender)

# TODO self detect high/crit min/max from output
# like Core 0:        +46.0 C  (high = +82.0 C, crit = +102.0 C)
# should detect a second warn=82 and red=102
    def parse_sensors(self, hostname, buf, sender):
        now = time.time()
        color = 'green'
        sbuf = f"{xytime(now)} - sensors Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error("ERROR: parse_sensors: host is None")
            return
        sline = buf.split("\n")
        for line in sline:
            if len(line) == 0:
                continue
            if line[0] == ' ':
                continue
            sbuf += line + '\n'
            #self.debug(f"DEBUG: check {line}XX")
            if len(line) > 0 and ':' not in line:
                #self.debug(f"DEBUG: {hostname} adapter={line}")
                adapter = line
            else:
                if "SENSOR" in H.rules and H.rules["SENSOR"] is not None:
                    ret = H.rules["SENSOR"].check(adapter, line)
                else:
                    ret = None
                if ret is None:
                    #self.debug("DEBUG: use global rules")
                    ret = self.rules["SENSOR"].check(adapter, line)
                if ret is not None:
                    sbuf += ret["txt"] + '\n'
                    color = setcolor(ret["color"], color)
                if ret is not None and 'v' in ret:
                    self.do_sensor_rrd(hostname, adapter, ret['sname'], ret['v'])
        ts_end = time.time()
        self.stat("parsesensor", ts_end - now)
        self.column_update(hostname, "sensor", color, time.time(), sbuf, 4 * 60, sender)

    def parse_df(self, hostname, buf, inode, sender):
        now = time.time()
        if inode:
            column = 'inode'
            S = "INODE"
        else:
            column = 'disk'
            S = "DISK"
        color = 'green'
        sbuf = f"{xytime(now)} - disk Ok\n"

        H = self.find_host(hostname)
        if H is None:
            self.error("ERROR: parse_ports: host is None")
            return
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
                color = ret["color"]
                if "pct" in ret:
                    pct = ret["pct"]
                    mnt = ret["mnt"]
            else:
                ret = self.rules[S].check(line)
                if ret is not None:
                    sbuf += ret["txt"] + '\n'
                    color = ret["color"]
                    if "pct" in ret:
                        pct = ret["pct"]
                        mnt = ret["mnt"]
            if pct is not None:
                self.do_rrd(hostname, column, mnt, pct)
        sbuf += buf
        self.column_update(hostname, column, color, time.time(), sbuf, 4 * 60, sender)
        return

    def parse_status(self, msg):
        self.debug(f"DEBUG: parse_status from {msg['addr']}")
        hdata = msg["buf"]
        column = None
        # only first line is important
        sline = hdata.split("\n")
        line = sline[0]
        sline = line.split(" ")
        hostcol = sline[1]
        color = sline[2]
        hc = hostcol.split(".")
        if len(hc) < 2:
            return False
        column = hc[-1]
        del(hc[-1])
        hostname = ".".join(hc)
        if color not in COLORS:
            self.error("ERROR: invalid color")
            return False
        expire = 30 * 60
        wstatus = sline[0].replace("status", "")
        if len(wstatus) > 0:
            # either group and/or +x
            if wstatus[0] == '+':
                delay = wstatus[1:]
                expire = xydelay(wstatus)
        self.debug("HOST.COL=%s %s %s color=%s expire=%d" % (sline[1], hostname, column, color, expire))

        if column is not None:
            self.column_update(hostname, column, color, time.time(), hdata, expire, msg["addr"])
        return False

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
        expire = time.time() + howlongs
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
            now = time.time()
            req = f'UPDATE columns SET ackcause="{why}", ackend={now + howlongs} WHERE hostname="{hostname}" AND column="{cname}" AND color != "green"'
            self.sqc.execute(req)
        return True

    def parse_disable(self, msg):
        self.debug(f"DISABLE ACTION {msg}")
        dstart = time.time()
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
        expire = time.time() + howlongs
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
            blue_status = f"Disabled until {xytime(expire)}\n\n{why}\n\nStatus message when disabled follows:\n\n"
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

    def parse_hostdata(self, msg):
        hdata = msg["buf"]
        hostname = None
        section = None
        buf = ""
        # non hostdata begin with status
        # hostdata begin with an empty line ?
        firstchars = hdata[0:6]
        #self.debug(firstchars)
        if firstchars == 'status':
            self.parse_status(msg)
            return
        if firstchars == 'acknow':
            self.parse_acknowledge(hdata)
            return
        if firstchars == 'disabl':
            self.parse_disable(hdata)
            return
        #self.debug("THIS IS HISTDATA")
        for line in hdata.split("\n"):
            line = line.rstrip()
            if len(line) == 0:
                continue
            if line[0] == '[' and line[len(line) - 1] == ']':
                if section is not None:
                    handled = False
                    if section == '[collector:]':
                        handled = True
                        for cline in buf.split("\n"):
                            if len(cline) == 0:
                                continue
                            if cline[0:6] == 'client':
                                scline = cline.split(" ")
                                cname = scline[1]
                                if cname.endswith(".linux"):
                                    hostname = cname.replace(".linux", "")
                        if hostname is None:
                            self.error("ERROR: no hostname in collector")
                            return
                    if section == '[free]':
                        handled = True
                        self.parse_free(hostname, buf, msg["addr"])
                    if section == '[uptime]':
                        handled = True
                        self.parse_uptime(hostname, buf, msg["addr"])
                    if section == '[df]':
                        handled = True
                        self.parse_df(hostname, buf, False, msg["addr"])
                    if section == '[inode]':
                        handled = True
                        self.parse_df(hostname, buf, True, msg["addr"])
                    if section == '[ports]':
                        handled = True
                        self.parse_ports(hostname, buf, msg["addr"])
                    if section == '[ss]':
                        handled = True
                        self.parse_ports(hostname, buf, msg["addr"])
                    if section == '[ps]':
                        handled = True
                        self.parse_ps(hostname, buf, msg["addr"])
                    if section == '[lmsensors]':
                        handled = True
                        self.parse_sensors(hostname, buf, msg["addr"])
                    if not handled:
                        self.debug(f"DEBUG: section {section} not handled")
                section = line
                buf = ""
                continue
            if section in ['[uptime]', '[ps]', '[df]', '[collector:]', '[inode]', '[free]', '[ports]', '[lmsensors]', '[mdstat]', '[ss]']:
                buf += line
                buf += '\n'
        if hostname is not None:
            self.save_hostdata(hostname, hdata, time.time())
        else:
            self.error("ERROR: invalid client data without hostname")
            if self.debug:
                print(msg)

    def unet_start(self):
        if os.path.exists(self.unixsock):
            os.unlink(self.unixsock)
        self.us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.us.bind(self.unixsock)
        # TODO does it is necessary ?, check setup with apache
        os.chmod(self.unixsock, 0o666)
        self.us.listen(10)
        self.us.setblocking(0)
        self.uclients = []
        self.debug("DEBUG: create unix socket")

    def unet_loop(self):
        try:
            c, addr = self.us.accept()
            self.uclients.append(c)
            c.setblocking(0)
        except socket.error:
            #self.debug("DEBUG: nobody")
            pass
        for C in self.uclients:
            try:
                rbuf = C.recv(64000)
                if not rbuf:
                    self.uclients.remove(C)
                    continue
            except socket.error:
                #self.debug("DEBUG: nothing to recv")
                continue
            buf = rbuf.decode("UTF8")
            sbuf = buf.split(" ")
            cmd = sbuf[0]
            if cmd == 'GETSTATUS':
                hostname = sbuf[1]
                service = sbuf[2].rstrip()
                if len(sbuf) > 3:
                    ts = xyts_(sbuf[3], None)
                else:
                    res = self.sqc.execute('SELECT ts FROM columns WHERE hostname == ? AND column == ?', (hostname, service))
                    results = self.sqc.fetchall()
                    if len(results) != 1:
                        C.send(b"ERROR: no service\n")
                        C.close()
                        continue
                    ts = results[0][0]
                data = self.gen_html("svcstatus", hostname, service, ts)
                try:
                    C.send(data.encode("UTF8"))
                except BrokenPipeError as error:
                    self.error("Client get away")
                    pass
            elif cmd == "acknowledge":
                self.parse_acknowledge(buf)
            elif cmd == "TLSproxy":
                lines = buf.split("\n")
                line = lines.pop(0)
                addr = line.split(" ")[1]
                buf = "\n".join(lines)
                #print("DEBUG: addr is {addr}")
                #print(buf)
                msg = {}
                msg["buf"] = buf
                msg["addr"] = f"TLS proxy for {addr}"
                self.parse_hostdata(msg)
            else:
                self.error(f"ERROR: Unkownw cmd {cmd}")
            C.close()

    def set_netport(self, port):
        if port < 0 or port > 65535:
            return False
        self.netport = port
        return True

    def net_start(self):
        if self.ipv6:
            self.s = socket.socket(socket.AF_INET6)
        else:
            self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.log('network', f"DEBUG: listen on {self.netport}")
        if self.ipv6:
            self.s.bind(("::", self.netport))
        else:
            self.s.bind(("0.0.0.0", self.netport))
        self.s.setblocking(0)
        self.clients = []
        self.s.listen(1000)

    def net_loop(self):
        now = time.time()
        try:
            c, addr = self.s.accept()
            c.setblocking(0)
            self.log('network', 'DEBUG: Got connection from %s' % str(addr))
            C = {}
            C["s"] = c
            C["t"] = now
            C["buf"] = ""
            # we need only IP
            C["addr"] = addr[0]
            self.clients.append(C)
        except socket.error:
            # self.debug("DEBUG: nobody")
            pass
        # readlist = []
        # for C in self.clients:
        #    readlist.append(C["s"])
        # rread, rwrite, rerror = select.select(readlist, [], readlist, 1)
        # print(rread)
        # print(rerror)
        for C in self.clients:
            client = C["s"]
            try:
                buf = client.recv(64000)
            except socket.error as e:
                if C["t"] + 30 < now:
                    self.debug(f'TIMEOUT client len={len(C["buf"])} addr=${C["addr"]}')
                    client.close()
                    self.parse_hostdata(C)
                    self.clients.remove(C)
                # else:
                #    self.debug("DEBUG: nothing to recv")
                # print(self.clients)
                # print(e)
                # return True
                continue
            if not buf:
                # self.debug("DEBUG: client disconnected")
                client.close()
                self.parse_hostdata(C)
                self.clients.remove(C)
            else:
                # self.debug(f"DEBUG: got data len={len(buf)}")
                C["buf"] += buf.decode("UTF8")
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
        ts_start = time.time()
        if self.xy_data is None:
            self.xy_data = self.xymon_replace("$XYMONVAR")
        self.histdir = self.xymon_replace("$XYMONHISTDIR/")
        self.xy_hostdata = self.xy_data + 'hostdata/'
        self.histlogs = self.xymon_replace("$XYMONHISTLOGS")
        self.serverdir = self.xymon_replace("$XYMONHOME")
        webdir = self.xymon_replace("$XYTHON_WEB")
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
        if self.xythonmode > 0:
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
        self.db = self.xt_data + '/xython.db'
        self.debug(f"DEBUG: DB is {self.db}")
        self.sqconn = sqlite3.connect(self.db)
        self.sqc = self.sqconn.cursor()
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS columns
            (hostname text, column text, ts date, expire date, color text, ackend date, ackcause text, UNIQUE(hostname, column))''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS history
            (hostname text, column text, ts date, duration int, color text, ocolor text)''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS tests
            (hostname text, column text, next date, UNIQUE(hostname, column))''')
        self.sqc.execute('DELETE FROM tests')
        self.read_configs()
        self.sqconn.commit()
        ts_end = time.time()
        self.has_pika = has_pika
        if self.has_pika:
            if not self.init_pika():
                self.has_pika = False
        self.debug("STAT: init loaded hist in %f" % (ts_end - ts_start))

# read hosts.cfg and analysis.cfg
# check if thoses files need to be reread
    def read_configs(self):
        ret = self.read_hosts()
        if ret == RET_ERR:
            self.error("ERROR: failed to read hosts")
            return False
        for H in self.xy_hosts:
            self.debug(f"DEBUG: init FOUND: {H.name}")
            if not self.read_hist(H.name):
                self.error(f"ERROR: failed to read hist for {H.name}")
            self.read_analysis(H.name)
        if ret == RET_NEW:
            self.gen_tests()
        return True

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
