import re

from xython.common import gcolor
from xython.common import tokenize
from xython.common import xydelay

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

class xy_rule_disk():
    def __init__(self, fs, warn, panic):
        self.fs = fs
        self.warn = warn
        self.panic = panic

    def check(self, pc):
        color = 'green'
        ret = {}
        if pc < self.warn:
            txt = f"&green {self.fs} {pc} < {self.warn}"
        elif pc >= self.warn and pc < self.panic:
            txt = f"&yellow {self.fs} {pc} > {self.warn}"
            color = 'yellow'
        if pc >= self.panic:
            txt = f"&red {self.fs} {pc} > {self.panic}"
            color = 'red'
        ret["txt"] = txt
        ret["color"] = color
        return ret


class xy_rule_disks():
    def __init__(self):
        self.rules = {}
        self.rrules = []
        self.ignore = {}
        self.rignore = []

    def dump(self):
        print(f"FS RULE {self.fs} warn={self.warn} panic={self.panic}")

    def add(self, fsruleline):
        tokens = tokenize(fsruleline)
        fs = tokens.pop(0)
        regex = False
        if fs[0] == '%':
            fs = fs[1:]
            regex = True
        if len(tokens) == 0:
            print("ERROR: fs:")
            return False
        if tokens[0] == 'IGNORE':
            if regex:
                self.rignore.append(fs)
            else:
                self.ignore[fs] = True
            return True
        if len(tokens) != 2:
            print("ERROR: fs: not enough tokens")
            return False
        warn = int(tokens.pop(0))
        panic = int(tokens.pop(0))
        xrd = xy_rule_disk(fs, warn, panic)
        if regex:
            self.rrules.append(xrd)
        else:
            self.rules[fs] = xrd
        return True

    def check(self, line):
        ret = {}
        line = re.sub(r"\s+", ' ', line)
        line = line.rstrip()
        sline = line.split(" ")
        part = sline[5]
        rawpc = sline[4]
        if rawpc[-1] != '%':
            print("ERROR: invalid percent")
            return None
        pc = int(rawpc.rstrip('%'))
        if part in self.ignore:
            return None
        for pignore in self.rignore:
            return None
        if part in self.rules:
            xrd = self.rules[part]
            return xrd.check(pc)
        for pr in self.rrules:
            ret = re.search(pr.fs, part)
            if ret:
                return pr.check(pc)
        return None


class xy_rule_cpu():
    def __init__(self):
        # defaults for LOAD
        self.loadset = False
        self.loadwarn = 5.0
        self.loadpanic = 10.0
        # defaults for UP (in seconds)
        self.upset = False
        self.bootlimit = 60
        self.toolonglimit = -1
        self.upcolor = 'yellow'
        # defaults for CLOCK
        self.maxoffset = None
        self.clockcolor = 'yellow'
        # used for tests
        self.xload = None
        self.xuptime = None

    def init_from(self, cline):
        tokens = tokenize(cline)
        keyword = tokens.pop(0)
        if keyword == 'UP':
            self.upset = True
            bl = tokens.pop(0)
            self.bootlimit = xydelay(bl)
            if len(tokens) == 0:
                return True
            bl = tokens.pop(0)
            self.toolonglimit = xydelay(bl)
            if len(tokens) == 0:
                return True
            self.upcolor = gcolor(tokens.pop(0))
            return True
        if keyword == 'LOAD':
            self.loadset = True
            self.loadwarn = float(tokens.pop(0))
            self.loadpanic = float(tokens.pop(0))
            return True
        if keyword == 'CLOCK':
            self.maxoffset = int(tokens.pop(0))
            self.clockcolor = gcolor(tokens.pop(0))
            return True
        return False

    def cpucheck(self, upline):
        ret = {}
        loadavg = re.search(r"load average[s]*: [0-9]+[,\.][0-9]+,\s([0-9]+[,\.][0-9]+),", upline)
        if not loadavg:
            print("ERROR: fail to find load")
            return None
        load = loadavg.group(1).replace(',', '.')
        self.xload = float(load)
        if self.xload >= self.loadpanic:
            ret["LOAD"] = {}
            ret["LOAD"]["color"] = 'red'
            ret["LOAD"]["txt"] = f'&red load {self.xload} > {self.loadpanic}\n'
        elif self.xload >= self.loadwarn:
            ret["LOAD"] = {}
            ret["LOAD"]["color"] = 'yellow'
            ret["LOAD"]["txt"] = f'&yellow load {self.xload} > {self.loadwarn}\n'
        else:
            ret["LOAD"] = {}
            ret["LOAD"]["color"] = 'green'
            ret["LOAD"]["txt"] = f'&green load {self.xload} < {self.loadwarn}\n'
        rup = re.search(r"up (.*),\s*[0-9]+\suser", upline)
        if not rup:
            # TODO return an ret["error"]
            print("ERROR: failed to find uptime")
            print(upline)
            return None
        sup = rup.group(1)
        sup.replace(",", '')
        self.xuptime = 0
        # convert HH:MM in minutes
        tmp = re.search(r'([0-9]+):([0-9][0-9])', sup)
        if tmp and tmp.lastindex == 2:
            self.xuptime += int(tmp.group(1)) * 60 + int(tmp.group(2))
        # convert x days in minutes
        tmp = re.search(r'([0-9]+)\s*day', sup)
        if tmp and tmp.lastindex == 1:
            self.xuptime += int(tmp.group(1)) * 24 * 60
        # convert x mins in minutes
        tmp = re.search(r'([0-9]+)\s*min', sup)
        if tmp and tmp.lastindex == 1:
            self.xuptime += int(tmp.group(1))
        # convert xxx.xx hours in minutes
        if self.xuptime <= self.bootlimit:
            ret["UP"] = {}
            ret["UP"]["color"] = self.upcolor
            ret["UP"]["txt"] = f'&yellow uptime {self.xuptime} < {self.bootlimit}'
        elif self.toolonglimit != -1 and self.xuptime >= self.toolonglimit:
            ret["UP"] = {}
            ret["UP"]["color"] = self.upcolor
            ret["UP"]["txt"] = f'&yellow uptime {self.xuptime} > {self.toolonglimit}'
        else:
            ret["UP"] = {}
            ret["UP"]["color"] = 'green'
            ret["UP"]["txt"] = f'&green uptime {self.xuptime} < {self.toolonglimit}'
        return ret


class xy_rule_mem():
    def __init__(self):
        self.name = None
        self.warn = 0
        self.panic = 0

    def init_from(self, memline):
        tokens = tokenize(memline)
        if len(tokens) != 2:
            return False
        self.warn = int(tokens.pop(0))
        self.panic = int(tokens.pop(0))
        return True

    def memcheck(self, buf, what):
        mem = re.search(r"Mem:\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)", buf)
        swap = re.search(r"Swap:\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)", buf)
        memtotal = int(int(mem.group(1)) / 1024)
        memused = int(int(mem.group(2)) / 1024)
        memusedpct = int(int(memused / memtotal * 100))
        memactfree = int(int(mem.group(6)) / 1024)
        memact = memtotal - memactfree
        memactpct = int(int(memact / memtotal * 100))
        swaptotal = int(int(swap.group(1)) / 1024)
        swapused = int(int(swap.group(2)) / 1024)
        if swaptotal == 0:
            swappct = 0
        else:
            swappct = int(swapused / swaptotal * 100)
        self.memtotal = memtotal
        self.memusedpct = memusedpct
        self.swaptotal = swaptotal
        self.swappct = swappct
        ret = {}
        color = 'green'
        if what == "MEMPHYS":
            T = 'Real/Physical'
            if memusedpct >= self.panic:
                color = 'red'
            elif memusedpct >= self.warn:
                color = 'yellow'
            ret["color"] = color
            ret["txt"] = f"&{color} {T:16}{memused:11}M{memtotal:11}M{memusedpct:11}%{self.warn:4} {self.panic:4}\n"
        if what == "MEMSWAP":
            T = 'Swap/Page'
            if swappct >= self.panic:
                color = 'red'
            elif swappct >= self.warn:
                color = 'yellow'
            ret["color"] = color
            ret["txt"] = f"&{color} {T:16}{swapused:11}M{swaptotal:11}M{swappct:11}%{self.warn:4} {self.panic:4}\n"
        if what == "MEMACT":
            T = 'Actual/Virtual'
            if memactpct >= self.panic:
                color = 'red'
            elif memactpct >= self.warn:
                color = 'yellow'
            ret["color"] = color
            ret["txt"] = f"&{color} {T:16}{memact:11}M{memtotal:11}M{memactpct:11}%{self.warn:4} {self.panic:4}\n"
        return ret


class xy_rule_proc():
    def __init__(self):
        self.name = None
        self.color = 'red'
        self.text = None
        self.min = 1
        self.max = -1
        self._count = 0

    def dump(self):
        print(f"PROC RULE {self.name} TEXT={self.text} min={self.min} max={self.max}")

    def init_from(self, portruleline):
        tokens = tokenize(portruleline)
        self.name = tokens.pop(0)
        if len(tokens) == 0:
            return
        self.min = int(tokens.pop(0))
        if len(tokens) == 0:
            return
        self.max = int(tokens.pop(0))
        if len(tokens) == 0:
            return
        self.color = tokens.pop(0)
        if len(tokens) == 0:
            return
        print("UNHANDLED")
        return

    def check(self, data):
        if self.text is None:
            self.text = self.name
        self._count = 0
        # test matching against data
        for line in data:
            line = re.sub(r"\s+", ' ', line)
            line = line.rstrip()
            ret = re.search(self.name, line)
            if not ret:
                continue
            self._count += 1
        ret = {}
        if self.max >= 0:
            txt = f"&green {self.text} (found {self._count}, req. {self.min} and less than {self.max})"
        else:
            txt = f"&green {self.text} (found {self._count}, req. {self.min} or more)"
        color = 'green'
        if self._count < self.min:
            txt = f"&red {self.text} (found {self._count}, req. {self.min} or more)"
            color = 'red'
        if self.max >= 0 and self._count > self.max:
            txt = f"&red {self.text} (found {self._count}, req. {self.max} or less)"
            color = 'red'
        ret["txt"] = txt
        ret["color"] = color
        return ret


class xy_rule_port():
    def __init__(self):
        self.local = None
        self.state = None
        self.rstate = None
        self.text = None
        self.min = 1
        self.max = -1
        self._count = 0

    def dump(self):
        print(f"PORT RULE {self.local} {self.state} {self.rstate} TEXT={self.text} min={self.min} max={self.max}")

    def init_from(self, portruleline):
        tokens = tokenize(portruleline)
        for token in tokens:
            toks = token.split("=")
            if len(toks) != 2:
                print("ERROR: rule_port: init")
                return None
            left = toks[0]
            right = toks[1]
            if toks[0] == 'LOCAL':
                if right[0] == '%':
                    self.local = right[1:]
                else:
                    self.local = right
            elif left == 'STATE' or left == 'state':
                if right[0] == '%':
                    self.rstate = right[1:]
                else:
                    self.state = right
            elif toks[0] == 'TEXT':
                self.text = right
            else:
                print("UNHANDLED %s" % left)

    def check(self, data):
        if self.text is None:
            self.text = ""
            if self.local:
                self.text += self.local + " "
            if self.state:
                self.text += self.state + " "
        self._count = 0
        # test matching against data
        for line in data:
            line = re.sub(r"\s+", ' ', line)
            line = line.rstrip()
            sline = line.split(" ")
            if len(sline) >= 5:
                # proto = sline[0]
                if self.local:
                    local = sline[3]
                    ret = re.search(self.local, local)
                    if not ret:
                        continue
                if self.rstate and len(sline) == 6:
                    state = sline[5]
                    ret = re.search(self.rstate, state)
                    if not ret:
                        continue
                if self.state and len(sline) == 6:
                    state = sline[5]
                    if self.state != state:
                        continue
                if self.state and len(sline) != 6:
                    continue
                if self.rstate and len(sline) != 6:
                    continue
                self._count += 1
        ret = {}
        txt = f"&green {self.text} (found {self._count}, req. {self.min} or more)"
        color = 'green'
        if self._count < self.min:
            txt = f"&red {self.text} (found {self._count}, req. {self.min} or more)"
            color = 'red'
        if self.max >= 0 and self._count > self.max:
            txt = f"&red {self.text} (found {self._count}, req. {self.max} or less)"
            color = 'red'
        ret["txt"] = txt
        ret["color"] = color
        return ret
