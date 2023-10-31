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
from .xython_tests import do_generic_proto
import celery
from .common import xytime
from .common import xytime_
from .common import xyts
from .common import xyts_
from .common import gcolor
from .common import gif
from .common import setcolor
from .common import xydhm
from .common import xydelay
from .common import COLORS
from .common import is_valid_hostname
from .common import is_valid_column

from .rules import xy_rule_disks
from .rules import xy_rule_port
from .rules import xy_rule_proc
from .rules import xy_rule_mem
from .rules import xy_rule_cpu
from .rules import xy_rule_sensors

RRD_COLOR = ["0000FF", "FF0000", "00CC00", "FF00FF", "555555", "880000", "000088", "008800",
             "008888", "888888", "880088", "FFFF00", "888800", "00FFFF", "00FF00", "AA8800",
             "AAAAAA", "DD8833", "DDCC33", "8888FF", "5555AA", "B428D3", "FF5555", "DDDDDD",
             "AAFFAA", "AAFFFF", "FFAAFF", "FFAA55", "55AAFF", "AA55FF"]

class xy_protocol:
    def __init__(self):
        self.send = None
        self.expect = None
        self.port = None
        self.options = None

class xy_host:
    def __init__(self, name):
        self.last_ping = 0
        self.name = name
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
        self.certs = {}
        self.sslwarn = 30
        self.sslalarm = 10

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
        self.xy_hosts = []
        self.tests = []
        self.xythonmode = 2
        self.uclients = []
        self.clients = []
        self.s = None
        self.us = None
        self.netport = 1984
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
        self.expires = []
        self.stats = {}
        self.uptime_start = time.time()
        self.etcdir = '/etc/xymon/'
        self.xt_logdir = "/var/log/xython/"
        self.wwwdir = None
        self.xy_data = None
        self.xt_data = None
        self.xt_rrd = None
        self.xt_state = None
        self.vars = {}
        self.debugs = []
        self.msgn = 0
        # to be compared with mtime of hosts.cfg
        self.time_read_hosts = 0
        # each time read_hosts is called, read_hosts_cnt is ++ abd all hosts found are set to this value
        # so all hosts with a lower value need to be removed
        self.read_hosts_cnt = 0
        self.daemon_name = "xythond"
        self.protocols = {}
        self.time_read_protocols = 0
        self.time_read_graphs = 0
        self.time_read_rrddef = 0
        self.time_read_xserver_cfg = 0
        self.xymonserver_cfg = {}
        self.graphscfg = {}
        self.rrddef = {}
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
        # at which interval state/client send their status
        # default 5 minute
        self.ST_INTERVAL = 5 * 60
        self.NETTEST_INTERVAL = 2 * 60
        self.XYTHOND_INTERVAL = 2 * 60
        self.GENPAGE_INTERVAL = 30

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

    # used only at start, expire is set to let enough time to arrive before purpleing
    def column_set(self, hostname, cname, color, ts, expire):
        color = gcolor(color)
        now = time.time()
        req = f'INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color) VALUES ("{hostname}", "{cname}", {ts}, {now} + {expire}, "{color}")'
        res = self.sqc.execute(req)

    def debug(self, buf):
        if self.lldebug:
            print(buf)

    def debugdev(self, facility, buf):
        if self.lldebug and facility in self.debugs:
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

    def load_xymonserver_cfg(self):
        pxserver = f"{self.etcdir}/xymonserver.cfg"
        try:
            mtime = os.path.getmtime(pxserver)
        except:
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
        section = None
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
                        if raw[i-1] != '\\':
                            break
                    value += raw[i]
                    i += 1
            self.xymonserver_cfg[var] = value
            self.debug(f"DEBUG: {var} = {value}")
        return self.RET_OK

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
                res = self.sqc.execute("SELECT DISTINCT column FROM columns where color != 'green' AND color != 'blue' ORDER BY column")
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
                res = self.sqc.execute('SELECT DISTINCT hostname FROM columns WHERE hostname IN (SELECT hostname WHERE color != "green" and color != "blue") ORDER by ackend, hostname')
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
            data.replace("\n", '<br>\n')
            #data = re.sub("\n", '<br>\n', data)
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
                ackinfo = ackinfos[0]
                ackend = ackinfo[0]
                if ackend is not None:
                    ackmsg = ackinfo[1]
                    html += f'<CENTER>Current acknowledgement: {ackmsg}<br>Next update at: {xytime(int(ackend))}</CENTER>\n'
            else:
                print(f"ackinfo is len={len(ackinfo)}")
            # TODO acknowledge is only for non-history and non-green
            #if gcolor != 'green':
            html += f'<CENTER>\n<form action="$XYMONSERVERCGIURL/xythoncgi.py" method="post">\n'
            html += '<input type="text" placeholder="61" SIZE=6 name="duration" required>\n'
            html += '<input type="text" placeholder="ack message" name="cause" required>\n'
            html += f'<input type="hidden" name="hostname" value="{hostname}">\n'
            html += f'<input type="hidden" name="service" value="{column}">\n'
            html += f'<input type="hidden" name="action" value="ack">\n'
            #html += f'<input type="hidden" name="returnurl" value="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hostname}&amp;SERVICE={column}">\n'
            html += '<button type="submit">Send ack</button></form>\n'
            html += '</CENTER>\n'

            html += f'<CENTER>\n<form action="$XYMONSERVERCGIURL/xythoncgi.py" method="post">\n'
            html += '<input type="text" placeholder="61" SIZE=6 name="duration" required>\n'
            html += '<input type="text" placeholder="disable message" name="cause" required>\n'
            html += f'<input type="hidden" name="hostname" value="{hostname}">\n'
            html += f'<input type="text" name="dservice" value="{column}">\n'
            html += f'<input type="hidden" name="service" value="{column}">\n'
            html += f'<input type="hidden" name="action" value="disable">\n'
            #html += f'<input type="hidden" name="returnurl" value="$XYMONSERVERCGIURL/xythoncgi.py?HOST={hostname}&amp;SERVICE={column}">\n'
            html += '<button type="submit">Send blue</button></form>\n'
            html += '</CENTER>\n'

            #html += f"Status valid until {xytime()}"

            if has_rrdtool:
                if column in self.rrd_column:
                    for rrdname in self.rrd_column[column]:
                        #html += f'<CENTER><img src="/xython/{hostname}/{rrdname}.png"></CENTER>'
                        html += f'<CENTER><img src="$XYMONSERVERCGIURL/showgraph.py?hostname={hostname}&service={rrdname}"></CENTER>'


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

    def read_snmp_hosts(self, hostname):
        H = self.find_host(hostname)
        fname = f"{self.etcdir}/snmp.d/{hostname}"
        try:
            f = open(fname)
        except FileNotFoundError:
            self.error(f"Fail to open {fname}")
            return False
        except:
            self.error(f"Fail to open {fname}")
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
                self.error(f"ERROR: invalid SNMP custom graph line {line}")
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
            self.rrd_column[obj] = obj

    def hosts_check_snmp_tags(self):
        for H in self.xy_hosts:
            if H.tags_read:
                continue
            need_conn = True
            for test in H.tags:
                if len(test) == 0:
                    continue
                if test == '#':
                    continue
                if test[0] == '#':
                    test = test[1:]
                if test[0:6] == 'testip':
                    H.use_ip = True
                    continue
                if test[0:4] == 'snmp':
                    snmp_tags = test.split(':')
                    for stag in snmp_tags:
                        self.debug(f"DEBUG: check SNMP TAG {stag}")
                        if stag in ['memory', 'disk']:
                            H.snmp_columns.append(stag)
                            continue
                        if stag[0:10] == 'community=':
                            H.snmp_community = stag.split('=')[1]
                            continue
                    self.read_snmp_hosts(H.name)

    def hosts_check_tags(self):
        for H in self.xy_hosts:
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
                tokens = tag.split(':')
                test = tokens[0]
                if test in self.protocols:
                    H.add_test(test, tag, None, test, True, False)
                    H.tags_known.append(tag)
                    H.dump()
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
                        self.error(f"INVALID {tag}")
                        continue
                    url = f"{tokens[1]};cont={tokens[2]}"
                    H.add_test("http", url, None, "http", True, False)
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'http':
                    url = tag
                    if tag[0:10] == 'httpstatus':
                        tokens = tag.split(';')
                        if len(tokens) != 3:
                            self.error(f"INVALID {tag}")
                            continue
                        url = f"{tokens[1]};httpcode={tokens[2]}"
                    self.debug("\tDEBUG: HTTP tests %s" % tag)
                    H.add_test("http", url, None, "http", True, False)
                    H.tags_known.append(tag)
                    continue
                if tag[0:4] == 'snmp':
                    H.tags_known.append(tag)
                    self.read_snmp_hosts(H.name)
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
                self.log("todo", f"TODO hosts: tag={tag}")
                self.debug(f"\tDEBUG: unknow tag={tag}xxx")
                H.tags_unknown.append(tag)
            if need_conn:
                H.add_test("conn", tag, None, "conn", True, False)
            self.gen_column_info(H.name)

# read hosts.cfg
# return RET_OK if nothing new was read
# return RET_ERR on error
# return RET_NEW if hosts.cfg was read
    def read_hosts(self):
        try:
            mtime = os.path.getmtime(self.etcdir + "/hosts.cfg")
        except:
            self.error("ERROR: cannot get mtime of hosts.cfg")
            return self.RET_ERR
        #self.debug(f"DEBUG: compare mtime={mtime} and time_read_hosts={self.time_read_hosts}")
        if self.time_read_hosts < mtime:
            self.time_read_hosts = mtime
        else:
            return self.RET_OK
        self.debug(f"DEBUG: read_hosts in {self.etcdir}")
        self.read_hosts_cnt += 1
        try:
            fhosts = open(self.etcdir + "/hosts.cfg", 'r')
        except:
            self.error("ERROR: cannot open hosts.cfg")
            return self.RET_ERR
        dhosts = fhosts.read()
        dhosts = dhosts.replace('\\\n', '')
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
            host_ip = sline.pop(0)
            host_name = sline.pop(0)
            if '/' in host_name:
                self.error(f"ERROR: invalid hostname {host_name}")
                continue
            self.debug("DEBUG: ip=%s host=%s" % (host_ip, host_name))
            # conn is enabled by default
            # if host already exists, remove it
            host_tags = None
            H = self.find_host(host_name)
            if H is not None:
                host_tags = H.tags
                self.xy_hosts.remove(H)
            H = xy_host(host_name)
            H.rhcnt = self.read_hosts_cnt
            H.hostip = host_ip
            if host_tags != sline:
                self.log(self.daemon_name, f"New host {H.name}")
            else:
                self.log(self.daemon_name, f"Known host {H.name}")
            H.tags = sline
            self.xy_hosts.append(H)
        for H in self.xy_hosts:
            if H.rhcnt < self.read_hosts_cnt:
                self.debug(f"DEBUG: read_hosts: purge {H.name}")
                self.xy_hosts.remove(H)
        return self.RET_NEW

    def read_protocols(self):
        mtime = os.path.getmtime(self.etcdir + "/protocols.cfg")
        #self.debug(f"DEBUG: compare mtime={mtime} and time_read_protocols={self.time_read_protocols}")
        if self.time_read_protocols < mtime:
            self.time_read_protocols = mtime
        else:
            return self.RET_OK
        try:
            fprotocols = open(self.etcdir + "/protocols.cfg", 'r')
        except:
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
                P.expect = line[8:len(line)-1]
                continue
            if line[0:6] == 'send "':
                if line[-1] != '"':
                    self.error(f"ERROR: wrong send format for {cproto}")
                    continue
                P.send = line[6:len(line)-1]
                P.send = P.send.replace('\\n', '\n')
                P.send = P.send.replace('\\r', '\r')
                continue
            self.debug(f"{cproto} unhandled {line}")
        return self.RET_OK

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
        cdata += f"IP: TODO\n"
        if H.client_version:
            cdata += f"Client S/W: {H.client_version}\n"
        cdata += f"TAGS={H.tags_known}\n"
        cdata += f"TAGS not handled {H.tags_unknown}\n"
        cdata += f"TAGS with error {H.tags_error}\n"
        if len(H.tags_unknown):
            color = 'yellow'
        if len(H.tags_error):
            color = 'red'
        # TODO infinite time
        self.column_update(hostname, "info", color, int(time.time()), cdata, 365 * 24 * 3600, "xythond")

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
        #self.debug(f"DEBUG: column_update {hostname} {cname} ts={ts} expire={expire}")
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
        res = self.sqc.execute('INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color, ackend, ackcause) VALUES (?, ?, ?, ?, ?, ?, ?)', (hostname, cname, ts, expiretime, color, ackend, ackcause))
        #self.sqconn.commit()
        if color == 'purple':
            #duplicate
            rdata = self.get_histlogs(hostname, cname, ots)
            if rdata is None:
                return
            data = ''.join(rdata["data"])
        self.save_histlogs(hostname, cname, data, ts, color, updater)
        self.save_state(hostname, cname, color, int(ts), int(expiretime))
        ts_end = time.time()
        self.stat("COLUPDATE", ts_end - ts_start)

    def save_state(self, hostname, cname, color, ts_start, ts_expire):
        if self.xythonmode == 0:
            return
        expdir = f"{self.xt_state}/{hostname}"
        if not os.path.exists(expdir):
            os.mkdir(expdir)
        fexpire = f"{expdir}/{cname}"
        f = open(fexpire, 'w')
        f.write(f"{color} {ts_start} {ts_expire}")
        f.close()

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
                #print(data)
                tokens = data.split(" ")
                if len(tokens) != 3:
                    self.error(f"ERROR: fail to load {expdir}/{cname}: invalid data")
                    continue
                color = tokens[0]
                ts_start = int(tokens[1])
                expire = int(tokens[2])
                #self.debug(f"DEBUG: expire of {hostname}.{cname} is {expire} {xytime(expire)}")
                self.column_set(hostname, cname, color, ts_start, expire)
            except:
                self.error(f"ERROR: fail to load {expdir}/{cname}")
                continue

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
                #self.debug(f"DEBUG: ignore dropped {name} {column}")
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
                #print(xytime(int(tsa)))
                #bbuf = self.get_histlogs(H.name, column, tsa)
                #print(xytime(int(tsb)))
                bbuf = self.get_histlogs(H.name, column, tsb)
                edate = bbuf['first'].replace('blue Disabled until ', '').rstrip()
                #self.debug(f"DEBUG: disable date is {edate}X")
                ets = xyts(edate, None)
                expire = ets - int(time.time())
                #print(expire)
            if self.readonly:
                self.column_update(H.name, column, st_new, int(tsb), None, 3 * 60, "xython")
            else:
                self.column_set(H.name, column, st_new, tsb, expire)
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
        now = int(time.time())
        ts_start = now
        req = f'SELECT * FROM columns WHERE expire < {now} AND color != "purple"'
        res = self.sqc.execute(req)
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
        for H in self.xy_hosts:
            for T in H.tests:
                self.debug("DEBUG: gentest %s %s" % (H.name, T.type))
                # self.debug(T.urls)
                tnext = now + randint(1, 10)
                res = self.sqc.execute(f'INSERT OR REPLACE INTO tests(hostname, column, next) VALUES ("{H.name}", "{T.type}", {tnext})')

    def dump_tests(self):
        for T in self.tests:
            print("%s %d" % (T.name, int(T.ts)))

    def dohttp(self, T):
        name = f"{T.hostname}_http"
        ctask = dohttp.delay(T.hostname, T.urls, T.column)
        self.celerytasks[name] = ctask
        self.celtasks.append(ctask)

    def doping(self, T):
        H = self.find_host(T.hostname)
        hostip = H.hostip
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
                    if T.type in self.protocols:
                        self.do_generic_proto(H, T)
                        continue
        res = self.sqc.execute(f'UPDATE tests SET next = {now} + {self.NETTEST_INTERVAL} WHERE next < {now}')
        ts_end = time.time()
        self.stat("tests", ts_end - ts_start)
        self.stat("tests-lag", lag)

    def do_tests_rip(self):
        self.celery_workers = celery.current_app.control.inspect().ping()
        if self.celery_workers is None:
            self.error("ERROR: no celery workers")
            return
        ts_start = time.time()
        # RIP celery tasks
        now = int(time.time())
        for ctask in self.celtasks:
            if ctask.ready():
                status = ctask.status
                if status == 'FAILURE':
                    self.celtasks.remove(ctask)
                    self.error("ERROR: celery task error")
                    # TODO better handle this problem, easy to generate by removing ping
                    continue
                ret = ctask.get()
                hostname = ret["hostname"]
                testtype = ret["type"]
                column = ret["column"]
                self.debugdev('celery', f'DEBUG: result for {ret["hostname"]} \t{ret["type"]}\t{ret["color"]}')
                self.column_update(ret["hostname"], ret["column"], ret["color"], now, ret["txt"], self.NETTEST_INTERVAL + 120, "xython-tests")
                if "certs" in ret:
                    #self.debug(f"DEBUG: result for {ret['hostname']} {ret['column']} has certificate")
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
                    del(self.celerytasks[name])
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
            #self.debug(f"DEBUG: sslcert handle {url}")
            cdata += f"<fieldset><legend>{url}</legend>\n"
            cdata += f"{H.certs[url]['txt']}\n"
            expire = H.certs[url]["expire"]
            if expire <= H.sslalarm:
                cdata += f"&red expire in {expire} days\n"
                color = setcolor('red', color)
            elif expire <= H.sslwarn:
                cdata += f"&yellow expire in {expire} days\n"
                color = setcolor('yellow', color)
            else:
                cdata += f"&green expire in {expire} days (WARN={H.sslwarn} CRIT={H.sslalarm})\n"
            cdata += f"</fieldset>\n"
        self.column_update(hostname, "sslcert", color, int(time.time()), cdata, 365 * 24 * 3600, "sslcert")

    # TODO hardcoded hostname
    def do_xythond(self):
        now = int(time.time())
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
        self.column_update(socket.gethostname(), "xythond", "green", now, buf, self.XYTHOND_INTERVAL + 60, "xythond")

    def scheduler(self):
        #self.debug("====================")
        now = time.time()
        if now > self.ts_tests + 5:
            self.do_tests()
            self.do_tests_rip()
            self.ts_tests = now
        if now > self.ts_check + 1:
            self.check_purples()
            self.check_acks()
            self.ts_check = now
        if now > self.ts_xythond + self.XYTHOND_INTERVAL:
            xythond_start = time.time()
            self.do_xythond()
            now = time.time()
            self.stat("xythond", now - xythond_start)
            self.ts_xythond = now

        if now > self.ts_page + self.GENPAGE_INTERVAL:
            ts_start = time.time()
            self.gen_html("nongreen", None, None, None)
            self.gen_html("all", None, None, None)
            ts_end = time.time()
            self.stat("HTML", ts_end - ts_start)
            self.ts_page = now
        if now > self.ts_read_configs + 60:
            self.read_configs()
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

    # read analysis.cfg
    def read_analysis(self, hostname):
        H = self.find_host(hostname)
        mtime = os.path.getmtime(f"{self.etcdir}/analysis.cfg")
        #self.debug(f"DEBUG: read_analysis: compare mtime={mtime} and {H.time_read_analysis}")
        if H.time_read_analysis < mtime:
            H.time_read_analysis = mtime
        else:
            return self.RET_OK
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
                        return self.RET_ERR
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
                        return self.RET_ERR
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
                        return self.RET_ERR
                    H.rules["PORT"].append(rp)
            elif line[0:4] == 'PROC':
                rp = xy_rule_proc()
                rr = rp.init_from(line[5:])
                if not rr:
                    self.error(f"ERROR: invalid line {line}")
                    continue
                if currhost == 'DEFAULT':
                    self.rules["PROC"].append(rp)
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return self.RET_ERR
                    H.rules["PROC"].append(rp)
            elif line[0:4] == 'DISK':
                if currhost == 'DEFAULT':
                    rxd = self.rules["DISK"]
                    rxd.add(line[5:])
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return self.RET_ERR
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
                        return self.RET_ERR
                    if H.rules["INODE"] is None:
                        H.rules["INODE"] = xy_rule_disks()
                    rxd = H.rules["INODE"]
                    rxd.add(line[6:])
            elif line[0:6] == 'SENSOR':
                #self.debug(f"DEBUG: {line}")
                if currhost == 'DEFAULT':
                    # TODO
                    self.rules["SENSOR"].add(line[7:])
                if currhost == hostname:
                    H = self.find_host(hostname)
                    if H is None:
                        self.error(f"ERROR: host is None for {hostname}")
                        return self.RET_ERR
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
        return self.RET_NEW

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
        except:
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
            self.error("ERROR: didnt found a default section in {prrddef}")
            return self.RET_ERR
        return self.RET_OK

    def load_graphs_cfg(self):
        pgraphs = f"{self.etcdir}/graphs.cfg"
        mtime = os.path.getmtime(pgraphs)
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
                #print(f"SECTION is {section}")
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
        rrdbuf = f"{xytime(time.time())} - xrrd\n"
        color = 'green'
        allrrds = os.listdir(basedir)
        if 'sensor' in allrrds:
            adapters = os.listdir(f"{basedir}/sensor/")
            for adapter in adapters:
                rrd_sensors = os.listdir(f"{basedir}/sensor/{adapter}/")
                for rrd_sensor in rrd_sensors:
                    allrrds.append(f"sensor/{adapter}/{rrd_sensor}")
        #print(f"DEBUG: allrrds={allrrds}")
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
            base = [pngpath,
                '--width=576', '--height=140',
                '--vertical-label="% Full"',
                '--start=end-96h'
                ]
            if 'YAXIS' in self.graphscfg[graph]:
                base.append(f'--vertical-label={self.graphscfg[graph]["YAXIS"]}')
            else:
                base.append(f'--vertical-label="unset"')
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
                    #print(f"DEBUG: sensor_rrd: adapter is {adapter}")
                    # remove adapter name
                    label = re.sub('/.*/', '', label)
                if graph == 'sensor' and sensor_adapter != adapter:
                    #print(f"DEBUG: sensor_rrd: add comment {adapter}")
                    sensor_adapter = adapter
                    base.append(f'COMMENT:{adapter}\\n')
                label = label.ljust(20)
                #print(f"DEBUG: label is {label}")
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
            rrdup = xytime(time.time()).replace(':', '\\:')
            base.append(f'COMMENT:Updated\\: {rrdup}')
            try:
                #ret = rrdtool.graph(base)
                # TODO check this ret
                rrdbuf += f"&green generate graph from {rrd} with template={graph}\n"
            except rrdtool.OperationalError as e:
                rrdbuf += f"&red Failed to generate RRD from {rrd} with template={graph} {e}\n"
                color = 'red'
            #os.chmod(pngpath, 0o644)
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
        #self.debug("GEN RRDS")
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
                self.debug(f"CHECK {rrd} vs {rrdpattern}<br>")
                if re.match(rrdpattern, rrd):
                    rrdlist.append(rrd)
        else:
            rrdpath = f'{basedir}/{service}.rrd'
            #print(rrdpath)
            if os.path.exists(rrdpath):
                rrdlist.append(f"{service}.rrd")
                #print("exists")
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
        self.debug(rrdlist)
        if len(rrdlist) == 0:
            return 'Status: 400 Bad Request\n\nERROR: RRD list is empty'
        base = ['-',
        '--width=576', '--height=140',
        '--vertical-label="% Full"',
        '--start=end-96h'
        ]
        if 'RRDGRAPHOPTS' in self.xymonserver_cfg:
            for rrdgopt in self.xymonserver_cfg['RRDGRAPHOPTS'].split(' '):
                base.append(rrdgopt)
        if 'YAXIS' in self.graphscfg[service]:
            base.append(f'--vertical-label={self.graphscfg[service]["YAXIS"]}')
        else:
            base.append(f'--vertical-label="unset"')
        if 'TITLE' in self.graphscfg[service]:
            base.append(f'--title={self.graphscfg[service]["TITLE"]} on {hostname}')
        else:
            base.append(f'--title={service} on {hostname}')
        i = 0
        sensor_adapter = None
        for rrd in rrdlist:
            fname = str(rrd.replace(".rrd", ""))
            rrdfpath = f"{basedir}/{rrd}"
            print(f"fnam={fname}")
            label = self.rrd_label(fname, 'conn')
            info = rrdtool.info(rrdfpath)
            template = self.graphscfg[service]["info"]
            if service == 'sensor':
                adapter = os.path.dirname(rrd).split('/')[-1]
            #print(f"DEBUG: sensor_rrd: adapter is {adapter}")
            # remove adapter name
                label = re.sub('/.*/', '', label)
            if service == 'sensor' and sensor_adapter != adapter:
            #print(f"DEBUG: sensor_rrd: add comment {adapter}")
                sensor_adapter = adapter
                base.append(f'COMMENT:{adapter}\\n')
            label = label.ljust(20)
            #print(f"DEBUG: label is {label}<br>")
            for line in template:
                for dsname in self.get_ds_name(info):
                    #print(f"DEBUG: dsname={dsname}<br>")
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
            #rrdup = xytime(time.time()).replace(':', '\\:')
            #base.append(f'COMMENT:Updated\\: {rrdup}')
        #print("==================<br>")
        #print(base)
        #print('<br>')
        try:
            ret = rrdtool.graphv(base)
        # TODO check this ret
        except rrdtool.OperationalError as e:
            self.error(f"Fail to generate RRD {str(e)}")
            return f'Status: 400 Bad Request\n\nERROR: {str(e)}'
        return b"Content-type: image/png\r\n\r\n" + ret['image']

    # give a DS name from a sensor name
    def rrd_getdsname(self, sname):
        dsname = sname.replace(" ", '_')
        # dsname is 19 char max
        if len(dsname) > 19:
            dsname = sname.replace(" ", '')
        return dsname[:19]

    def get_ds_name(self, l):
        r = []
        for k in l.keys():
            if len(k) > 4:
                if k[-4:] == 'type':
                    ds = k.split('[')[1].split(']')[0]
                    r.append(ds)
        return r

    def do_rrd(self, hostname, rrdname, obj, dsname, value, dsspec):
        #self.debug(f"DEBUG: do_rrd for {hostname} {rrdname} {obj} {dsname} {value}")
        if not has_rrdtool:
            return False
        fname = self.rrd_pathname(rrdname, obj)
        rrdpath = f"{self.xt_rrd}/{hostname}"
        if not os.path.exists(rrdpath):
            os.mkdir(rrdpath)
            os.chmod(rrdpath, 0o755)
        rrdfpath = f"{self.xt_rrd}/{hostname}/{fname}.rrd"
        if not os.path.exists(rrdfpath):
            self.debug(f"DEBUG: do_rrd create for {hostname} {rrdname} {dsname} {value}")
            if rrdname in self.rrddef:
                rras = self.rrddef[rrdname]["info"]
            elif 'default' in self.rrddef:
                rras = self.rrddef['default']["info"]
            else:
                # this should not happen
                rras = "RRA:AVERAGE:0.5:1:1200"
            print(rras)
            rrdtool.create(rrdfpath, "--start", "now", "--step", "60",
                rras, dsspec);
        rrdtool.update(rrdfpath, f'-t{dsname}', f"N:{value}")
        return True

    def do_sensor_rrd(self, hostname, adapter, sname, value):
        #self.debug(f"DEBUG: do_sensor_rrd for {hostname} {adapter} {sname} {value}")
        if not has_rrdtool:
            return
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
        #self.debug(f"DEBUG: create {rrdfpath} with dsname={dsname}")
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
        ts_start = time.time()
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_free: host is None for {hostname}")
            return False
        now = int(time.time())
        #self.debug(f"DEBUG: parse_free for {hostname}")
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
            rrdmemtype = 'real'
            if memtype == 'MEMACT':
                rrdmemtype = 'actual'
            if memtype == 'MEMSWAP':
                rrdmemtype = 'swap'
            self.do_rrd(hostname, 'memory', rrdmemtype, 'realmempct', ret['v'], ['DS:realmempct:GAUGE:600:0:U'])

        sbuf += buf
        self.column_update(hostname, "memory", color, now, sbuf, self.ST_INTERVAL + 60, sender)
        self.stat("PARSEFREE", time.time() - ts_start)
        return True

    # TODO Machine has been up more than 0 days
    def parse_uptime(self, hostname, buf, sender):
        now = int(time.time())
        color = 'green'
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_uptime: host is None for {hostname}")
            return
        udisplay = re.sub(r"^.*up ", "up", buf)
        sbuf = f"{xytime(now)} {udisplay}\n"
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
        self.column_update(hostname, "cpu", color, now, sbuf, self.ST_INTERVAL + 60, sender)

    def parse_ps(self, hostname, buf, sender):
        now = int(time.time())
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
        self.column_update(hostname, "procs", color, now, sbuf, self.ST_INTERVAL + 60, sender)

    # TODO
    def parse_mdstat(self, hostname, buf, sender):
        now = int(time.time())
        devices = []
        color = 'green'
        sbuf = f"{xytime(now)} - RAID Ok\n"
        H = self.find_host(hostname)
        if H is None:
            self.error(f"ERROR: parse_mdstat: host is None for {hostname}")
            return
        sline = buf.split("\n")
        for line in sline:
            mdname = re.search(r"^[a-zA-Z0-9]\s:", line)
            if mdname is None:
                continue
        if len(devices) == 0:
            return
        sbuf += buf
        self.column_update(hostname, "raid", color, now, sbuf, self.ST_INTERVAL + 60, sender)

    #TODO
    def parse_ports(self, hostname, buf, sender):
        now = int(time.time())
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
        self.column_update(hostname, "ports", color, now, sbuf, self.ST_INTERVAL + 60, sender)

# TODO self detect high/crit min/max from output
# like Core 0:        +46.0 C  (high = +82.0 C, crit = +102.0 C)
# should detect a second warn=82 and red=102
    def parse_sensors(self, hostname, buf, sender):
        now = int(time.time())
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
        self.column_update(hostname, "sensor", color, now, sbuf, self.ST_INTERVAL + 60, sender)

    def parse_df(self, hostname, buf, inode, sender):
        now = int(time.time())
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
                self.do_rrd(hostname, column, mnt, 'pct', pct, ['DS:pct:GAUGE:600:0:100'])
        sbuf += buf
        self.column_update(hostname, column, color, now, sbuf, self.ST_INTERVAL + 60, sender)
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
            self.error(f"ERROR: invalid color {color}")
            return False
        expire = 30 * 60
        wstatus = sline[0].replace("status", "")
        if len(wstatus) > 0:
            # either group and/or +x
            if wstatus[0] == '+':
                delay = wstatus[1:]
                expire = xydelay(wstatus)
        self.debug("DEBUG: HOST.COL=%s %s %s color=%s expire=%d" % (sline[1], hostname, column, color, expire))

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
                self.debug(f"DEBUG: expired ack")
                # TODO ignore it and delete it
                continue
            why = ' '.join(tokens)
            self.debug(f"DEBUG: ack {hostname}.{cname} until {xytime(expire)} why={why}")
            self.do_ack(hostname, cname, expire, why)

    def store_ack(self, hostname, column, start, expire, msg):
        fname = f"{self.xt_acks}/{xytime_(start)}"
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
            #print("======================================")
            #print(line)
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
            print((ackend - now)/ 60)
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
        hdata += "\n[end]\n"
        for line in hdata.split("\n"):
            line = line.rstrip()
            if len(line) == 0:
                continue
            #self.debug(f"DEBUG: section={section} line={line}")
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
                                if len(scline) < 2:
                                    continue
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
                    if section == '[mdstat]':
                        handled = True
                        self.parse_mdstat(hostname, buf, msg["addr"])
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
                    if section == '[osversion]':
                        handled = True
                        H = self.find_host(hostname)
                        if H is not None:
                            H.osversion = buf
                        self.gen_column_info(hostname)
                    #if not handled:
                    #    self.debug(f"DEBUG: section {section} not handled")
                section = line
                buf = ""
                continue
            if section in ['[uptime]', '[ps]', '[df]', '[collector:]', '[inode]', '[free]', '[ports]', '[lmsensors]', '[mdstat]', '[ss]', '[clientversion]', '[uname]', '[osversion]']:
                buf += line
                buf += '\n'
        if hostname is not None:
            self.save_hostdata(hostname, hdata, time.time())
        else:
            self.error("ERROR: invalid client data without hostname")
            if self.debug:
                print(msg)

    def unet_send(self, buf):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.unixsock)
        except:
            self.error(f"FAIL to connect to xythond sock {self.unixsock}")
            return False
        sock.send(buf.encode("UTF8"))
        sock.close()
        return True

    def unet_send_recv(self, buf):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(self.unixsock)
        except:
            self.error(f"FAIL to connect to xythond sock {self.unixsock}")
            return None
        sock.send(buf.encode("UTF8"))
        self.unet_loop()
        buf = sock.recv(64000)
        sock.close()
        return buf

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
        return True

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
                if not is_valid_column(service):
                    smsg = f"ERROR: service has invalid name {service}\n"
                    C.send(smsg.encode("UTF8"))
                    C.close()
                    continue
                if len(sbuf) > 3:
                    ts = xyts_(sbuf[3], None)
                else:
                    res = self.sqc.execute('SELECT ts FROM columns WHERE hostname == ? AND column == ?', (hostname, service))
                    results = self.sqc.fetchall()
                    if len(results) != 1:
                        smsg = f"ERROR: no service named {service}\n"
                        C.send(smsg.encode("UTF8"))
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
            elif cmd == "disable":
                self.parse_disable(buf)
            elif cmd[0:6] == "proxy:":
                lines = buf.split("\n")
                line = lines.pop(0)
                buf = "\n".join(lines)
                msg = {}
                msg["buf"] = buf
                msg["addr"] = line.split(':')[1]
                self.parse_hostdata(msg)
            elif cmd[0:6] == "status":
                msg = {}
                msg["buf"] = buf
                msg["addr"] = 'local'
                self.parse_status(msg)
            elif cmd == "TLSproxy":
                lines = buf.split("\n")
                line = lines.pop(0)
                addr = line.split(" ")[1]
                buf = "\n".join(lines)
                msg = {}
                msg["buf"] = buf
                msg["addr"] = f"TLS proxy for {addr}"
                self.parse_hostdata(msg)
            elif cmd == 'GETRRD':
                self.debug(sbuf)
                if len(sbuf) < 4:
                    C.send(b'Status: 400 Bad Request\n\nERROR: not enough arguments')
                    C.close()
                    continue
                ret = self.gen_cgi_rrd(sbuf[1], sbuf[2], sbuf[3])
                try:
                    if type(ret) == str:
                        C.send(ret.encode("UTF8"))
                    else:
                        C.send(ret)
                except BrokenPipeError as error:
                    self.error("Client get away")
                    pass
            else:
                self.error(f"ERROR: Unknow cmd {cmd}")
            C.close()

    def set_netport(self, port):
        if port <= 0 or port > 65535:
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
                    self.debug(f'TIMEOUT client len={len(C["buf"])} addr={C["addr"]}')
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
        self.has_pika = has_pika
        if self.has_pika:
            if not self.init_pika():
                self.has_pika = False
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
        self.xt_acks = f"{self.xt_data}/acks/"
        self.xt_state = f"{self.xt_data}/state/"
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
        self.db = self.xt_data + '/xython.db'
        self.debug(f"DEBUG: DB is {self.db}")
        print(f"DEBUG: DB === {self.db}")
        # we always restart with a clean DB
        if os.path.exists(self.db):
            os.remove(self.db)
        self.sqconn = sqlite3.connect(self.db)
        self.sqc = self.sqconn.cursor()
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS columns
            (hostname text, column text, ts date, expire date, color text, ackend date, ackcause text, UNIQUE(hostname, column))''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS history
            (hostname text, column text, ts date, duration int, color text, ocolor text)''')
        self.sqc.execute('''CREATE TABLE IF NOT EXISTS tests
            (hostname text, column text, next date, UNIQUE(hostname, column))''')
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
        for H in self.xy_hosts:
            #self.debug(f"DEBUG: init FOUND: {H.name}")
            if not self.read_hist(H.name):
                self.error(f"ERROR: failed to read hist for {H.name}")
            self.read_analysis(H.name)
        if ret == self.RET_NEW:
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
