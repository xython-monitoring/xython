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

    def check(self, mnt, pc):
        color = 'green'
        ret = {}
        if pc < self.warn:
            txt = f"&green {mnt} {pc} < {self.warn} matchrule={self.fs}"
        elif pc >= self.warn and pc < self.panic:
            txt = f"&yellow {mnt} {pc} > {self.warn} matchrule={self.fs}"
            color = 'yellow'
        if pc >= self.panic:
            txt = f"&red {mnt} {pc} > {self.panic} matchrule={self.fs}"
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
            return xrd.check(part, pc)
        for pr in self.rrules:
            ret = re.search(pr.fs, part)
            if ret:
                return pr.check(part, pc)
        return None


# cannot use -1 since it is possible value
SENSOR_DISABLE = -400


class xy_rule_sensor():
    def __init__(self, warn, panic, mwarn, mpanic):
        self.warn = warn
        self.panic = panic
        self.mwarn = mwarn
        self.mpanic = mpanic

    def check(self, sname, pc):
        color = 'green'
        print(f"DEBUG: check {self.mpanic} {self.mwarn} {self.warn} {self.panic} vs {pc}")
        ret = {}
        if pc < self.warn:
            if self.mwarn != SENSOR_DISABLE:
                txt = f"&green {sname} {self.mwarn} < {pc} < {self.warn}"
            else:
                txt = f"&green {sname} {pc} < {self.warn}"
        elif pc >= self.warn and pc < self.panic:
            txt = f"&yellow {sname} {pc} => {self.warn}"
            color = 'yellow'
        if pc >= self.panic:
            txt = f"&red {sname} {pc} => {self.panic}"
            color = 'red'
        if self.mwarn != SENSOR_DISABLE and pc <= self.mwarn:
            txt = f"&yellow {sname} {pc} <= MINWARN={self.mwarn}"
            color = 'yellow'
        if self.mpanic != SENSOR_DISABLE and pc <= self.mpanic:
            txt = f"&red {sname} {pc} <= MINPANIC={self.mpanic}"
            color = 'red'
        ret["txt"] = txt
        ret["color"] = color
        return ret


# SENSOR adaptername sensorname warn panic
class xy_rule_sensors():
    def __init__(self):
        self.rules = {}

    def dump(self):
        print(f"SENSORS RULE {self.name} warn={self.warn} panic={self.panic}")

    def add(self, sensorruleline):
        print("===========================================================")
        print(f"DEBUG: add {sensorruleline}")
        sensorruleline = re.sub(r"\s+", ' ', sensorruleline)
        tokens = tokenize(sensorruleline)
        adapter = tokens.pop(0)
        sname = tokens.pop(0)
        regex = False
        if adapter[0] == '%':
            adapter = adapter[1:]
            regex = True
        print(f"DEBUG: adapter is {adapter}, sname is {sname}")
        if adapter not in self.rules:
            self.rules[adapter] = {}
            self.rules[adapter]["rules"] = {}
            self.rules[adapter]["regex"] = regex
        if len(tokens) == 0:
            print("ERROR: sensor:")
            return False
        if tokens[0] == 'IGNORE':
            self.rules[adapter]["ignore"] = True
            return True
        if len(tokens) < 2:
            print(f"ERROR: sensor: not enough tokens got {tokens}")
            return False
        warn = int(tokens.pop(0))
        panic = int(tokens.pop(0))
        if len(tokens) > 0:
            mwarn = int(tokens.pop(0))
        else:
            mwarn = SENSOR_DISABLE
        if len(tokens) > 0:
            mpanic = int(tokens.pop(0))
        else:
            mpanic = SENSOR_DISABLE
        xrd = xy_rule_sensor(warn, panic, mwarn, mpanic)
        regex = False
        if sname[0] == '%':
            sname = sname.lstrip('%')
            regex = True
        print(f"DEBUG: sname is {sname}")
        self.rules[adapter]["rules"][sname] = {}
        self.rules[adapter]["rules"][sname]["rule"] = xrd
        self.rules[adapter]["rules"][sname]["regex"] = regex
        return True

# return name of sensor, or None
    def is_sensor(self, line):
        #print(f"DEBUG: is {line} sensor ?")
        if len(line) < 4:
            return None
        sline = line.split(":")
        if len(sline) != 2:
            return None
        sname = sline[0]
        if sname == 'Adapter':
            return None
        line = sline[1]
        line = re.sub(r"^^\s+", '', line)
        #line = re.sub(r"\s+", ' ', line)
        line = line.replace("°C", " °C")
        sline = line.split(' ')
        #print(sline)
        if len(sline) < 2:
            #print("DEBUG: not enough token")
            return None
        if sline[1] == 'RPM':
            return [sname, sline[0], 'RPM']
        if sline[1] == 'V':
            return [sname, sline[0], 'V']
        if sline[1] == 'mV':
            return [sname, sline[0], 'V']
        if sline[1] == 'W':
            return [sname, sline[0], 'W']
        # °C and C related to locale
        if sline[1] == '°C' or sline[1] == 'C':
            return [sname, sline[0].lstrip("+"), 'C']
        #TODO joule J ?
        print("DEBUG: did not found a known unit")
        return None

    def find_rule_for_adapter(self, rule, sname):
        #print(f"DEBUG: find_rule_for_adapter {sname}")
        if sname in rule["rules"]:
            #print(f"DEBUG: exact match for {sname}")
            return rule["rules"][sname]["rule"]
        for srul in rule["rules"]:
            #print(f"TRY {srul}")
            if "regex" not in rule["rules"][srul] or not rule["rules"][srul]["regex"]:
                continue
            #print(f"DEBUG: search for {sname} with regex={srul}")
            ret = re.search(srul, sname)
            if ret:
                return rule["rules"][srul]["rule"]
        return None

    def check(self, adapter, line):
        #print("DEBUG: ======================================")
        #print(f"DEBUG: adapter={adapter} line={line}")
        #print(self.rules)
        ret = self.is_sensor(line)
        if ret is None:
            return None
        sname = ret[0]
        rawv = ret[1]
        sunit = ret[2]

        print(f"DEBUG: {sname} has value {rawv}")
        if adapter in self.rules:
            #print(f"DEBUG: adapter direct match for {adapter}")
            rule = self.rules[adapter]
            rs = self.find_rule_for_adapter(rule, sname)
            if rs is not None:
                return rs.check(sname, float(rawv))
        #print(f"DEBUG: check {adapter} via regex")
        # now check for regex
        for adapt in self.rules:
            if "regex" not in self.rules[adapt]:
                continue
            #print(f"DEBUG: regex is {adapt}")
            ret = re.search(adapt, adapter)
            if ret:
                #print(f"DEBUG: regex is {adapt} and match {self.rules[adapt]}")
                rs = self.find_rule_for_adapter(self.rules[adapt], sname)
                if rs is not None:
                    return rs.check(sname, float(rawv))

        #print("DEBUG: default search")
        # no rule matched, so we need to go back to default rule
        if "DEFAULT" not in self.rules:
            # no default
            print("DEBUG: no default")
            return None
        if sunit not in self.rules["DEFAULT"]["rules"]:
            print(f"DEBUG: no {sunit} in DEFAULT")
            return None
        rule = self.rules["DEFAULT"]["rules"][sunit]["rule"]
        return rule.check(sname, float(rawv))


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
            ret["txt"] = f"&{color} {T:16}{memused:11}M{memtotal:11}M{memusedpct:11}% WARN={self.warn:4} PANIC={self.panic:4}\n"
        if what == "MEMSWAP":
            T = 'Swap/Page'
            if swappct >= self.panic:
                color = 'red'
            elif swappct >= self.warn:
                color = 'yellow'
            ret["color"] = color
            ret["txt"] = f"&{color} {T:16}{swapused:11}M{swaptotal:11}M{swappct:11}% WARN={self.warn:4} PANIC={self.panic:4}\n"
        if what == "MEMACT":
            T = 'Actual/Virtual'
            if memactpct >= self.panic:
                color = 'red'
            elif memactpct >= self.warn:
                color = 'yellow'
            ret["color"] = color
            ret["txt"] = f"&{color} {T:16}{memact:11}M{memtotal:11}M{memactpct:11}% WARN={self.warn:4} PANIC={self.panic:4}\n"
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
