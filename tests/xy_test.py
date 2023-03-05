#!/usr/bin/env python3

import pytest
import time
from xython.common import gcolor
from xython.common import gif
from xython.common import tokenize
from xython.common import xydhm
from xython.common import xytime
from xython.common import xytime_
from xython.common import xyts
from xython.common import xyts_
from xython.common import xydelay
from xython.common import setcolor
from xython.rules import xy_rule_disks
from xython.rules import xy_rule_port
from xython.rules import xy_rule_proc
from xython.rules import xy_rule_mem
from xython.rules import xy_rule_cpu
from xython.xython import xythonsrv


def test_xytime():
    assert xytime(1678871776) == 'Wed Mar 15 10:16:16 2023'
    assert xyts('Wed Mar 15 10:16:16 2023', 'CET') == 1678871776
    assert xyts_('Wed_Mar_15_10:16:16_2023', 'CET') == 1678871776
    assert xytime(1328630692) == 'Tue Feb 7 17:04:52 2012'
    assert xytime_(1328630692) == 'Tue_Feb_7_17:04:52_2012'
    assert xyts_('Tue_Feb_7_17:04:52_2012', 'CET') == 1328630692
    assert xyts('Tue Feb 7 17:04:52 2012', 'CET') == 1328630692


def test_git():
    now = time.time()
    assert gif("red", now) == 'red-recent.gif'
    assert gif("red", now - 300) == 'red.gif'


def test_color():
    assert gcolor("pu") == 'purple'
    assert gcolor("re") == 'red'
    assert gcolor("ye") == 'yellow'
    assert gcolor("gr") == 'green'
    assert gcolor("bl") == 'blue'
    assert gcolor("cl") == 'clear'
    assert gcolor("plop") == 'purple'


def test_tokenize1():
    tok = tokenize('LOCAL=:22 state=LISTEN TEXT=SSH')
    assert len(tok) == 3


def test_tokenize2():
    tok = tokenize('LOCAL=%[.:]5500$ STATE=LISTEN "TEXT=SSH listener"')
    assert len(tok) == 3
    tok = tokenize('LOCAL=%[.:]22$ STATE= "LISTEN" "TEXT=SSH listener"')
    assert len(tok) == 3


def test_port_rule():
    rp = xy_rule_port()
    rp.init_from('LOCAL=:22 state=LISTEN TEXT=SSH')
    assert rp.local == ':22'
    assert rp.state == 'LISTEN'
    assert rp.text == 'SSH'

    rp = xy_rule_port()
    rp.init_from('LOCAL=%:22 state=LISTEN TEXT=SSH')
    assert rp.local == ':22'
    assert rp.state == 'LISTEN'
    assert rp.text == 'SSH'

    rp = xy_rule_port()
    rp.init_from('"LOCAL=:22" state=%LISTEN TEXT=SSH')
    assert rp.local == ':22'
    assert rp.state is None
    assert rp.rstate == 'LISTEN'
    assert rp.text == 'SSH'

    rp = xy_rule_port()
    rp.init_from('"LOCAL=:22" state=%LISTEN "TEXT=SSH listener"')
    assert rp.local == ':22'
    assert rp.state is None
    assert rp.rstate == 'LISTEN'
    assert rp.text == 'SSH listener'


def test_port_rule_smtps():
    rp = xy_rule_port()
    rp.init_from('"LOCAL=%([.:]465)$" state=LISTEN TEXT=smtps')
    assert rp.local == '([.:]465)$'
    assert rp.state == 'LISTEN'
    assert rp.rstate is None
    assert rp.text == 'smtps'


def test_port_check():
    f = open("./tests/ports/1678699830")
    data = f.readlines()
    f.close()
    rp = xy_rule_port()
    rp.init_from('LOCAL=%:22 state=LISTEN TEXT=SSH')
    rp.check(data)
    assert rp._count == 2

    rp = xy_rule_port()
    rp.init_from('LOCAL=0.0.0.0:69 state=LISTEN TEXT=TFTP')
    rp.check(data)
    assert rp._count == 0

    rp = xy_rule_port()
    rp.init_from('LOCAL=:111 state=LISTEN TEXT=TFTP')
    rp.check(data)
    assert rp._count == 2

    rp = xy_rule_port()
    rp.init_from('LOCAL=:111 TEXT=TFTP')
    rp.check(data)
    assert rp._count == 4


def test_proc_rule1():
    rp = xy_rule_proc()
    rp.init_from('ssh')
    assert rp.name == 'ssh'
    assert rp.min == 1
    assert rp.max == -1
    assert rp.text is None
    assert rp.color == 'red'


def test_proc_rule2():
    rp = xy_rule_proc()
    rp.init_from('ssh 4')
    assert rp.name == 'ssh'
    assert rp.min == 4
    assert rp.max == -1
    assert rp.text is None
    assert rp.color == 'red'


def test_proc_rule3():
    rp = xy_rule_proc()
    rp.init_from('ssh 4 5')
    assert rp.name == 'ssh'
    assert rp.min == 4
    assert rp.max == 5
    assert rp.text is None
    assert rp.color == 'red'


def test_proc_rule4():
    rp = xy_rule_proc()
    rp.init_from('ssh 4 7 yellow')
    assert rp.name == 'ssh'
    assert rp.min == 4
    assert rp.max == 7
    assert rp.color == 'yellow'
    assert rp.text is None


def test_proc_check():
    f = open("./tests/procs/1678875362")
    data = f.readlines()
    f.close()
    rp = xy_rule_proc()
    rp.init_from('ssh 1 4')
    ret = rp.check(data)
    assert rp._count == 5
    assert ret["color"] == 'red'

    rp = xy_rule_proc()
    rp.init_from('ntp 7 9')
    ret = rp.check(data)
    assert rp._count == 1
    assert ret["color"] == 'red'

    rp = xy_rule_proc()
    rp.init_from('"ser2net4 -c /etc/ser2net.yaml" 1 4')
    ret = rp.check(data)
    assert rp._count == 1
    assert rp.min == 1
    assert rp.max == 4
    assert ret["color"] == 'green'

    rp = xy_rule_proc()
    rp.init_from('"/usr/bin/cf-execd" 1 1')
    ret = rp.check(data)
    assert rp.min == 1
    assert rp.max == 1
    assert rp._count == 2
    assert ret["color"] == 'red'


def test_proc_disk():
    f = open("./tests/disk/test0")
    data = f.readlines()
    f.close()

    xrd = xy_rule_disks()
    xrd.add('/ 10 30')
    assert xrd.rules['/'].warn == 10
    assert xrd.rules['/'].panic == 30
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  90% /")
    assert ret["color"] == "red"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  10% /")
    assert ret["color"] == "yellow"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  0% /")
    assert ret["color"] == "green"

    xrd = xy_rule_disks()
    xrd.add('/ 98 99')
    xrd.add('%.* 90 95')
    assert xrd.rules['/'].warn == 98
    assert xrd.rules['/'].panic == 99
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  95% /")
    assert ret["color"] == "green"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  90% /")
    assert ret["color"] == "green"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  0% /")
    assert ret["color"] == "green"

    xrd = xy_rule_disks()
    xrd.add('%.* 90 95')
    #assert xrd.rules['/'].warn == 98
    #assert xrd.rules['/'].panic == 99
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  95% /")
    assert ret["color"] == "red"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  90% /")
    assert ret["color"] == "yellow"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  0% /")
    assert ret["color"] == "green"


def test_rule_mem():
    f = open("./tests/memory/test1")
    data = f.read()
    f.close()
    xm = xy_rule_mem()
    xm.init_from("10 20")
    assert xm.warn == 10
    assert xm.panic == 20
    ret = xm.memcheck(data, "MEMACT")
    assert xm.memtotal == 32029
    assert xm.memusedpct == 26

    f = open("./tests/memory/test2")
    data = f.read()
    f.close()
    print(data)
    xm = xy_rule_mem()
    xm.init_from("10 20")
    assert xm.warn == 10
    assert xm.panic == 20
    ret = xm.memcheck(data, "MEMSWAP")
    assert xm.swaptotal == 1000
    assert xm.swappct == 50
    assert ret["color"] == 'red'


def test_xydelay():
    assert xydelay('60') == 60
    assert xydelay('10m') == 600
    assert xydelay('1h') == 3600
    assert xydelay('1d') == 3600 * 24
    assert xydelay('1w') == 3600 * 24 * 7
    assert xydelay('-1') == -1
    with pytest.raises(SystemExit):
        xydelay('60x')
    with pytest.raises(SystemExit):
        xydelay('test')
    with pytest.raises(SystemExit):
        xydelay('tesh')


DAY_M = 60 * 24


def test_rule_cpu():
    xrc = xy_rule_cpu()
    xrc.init_from("UP 1h")
    xrc.init_from("LOAD 4.7 88.9")
    assert xrc.loadwarn == 4.7
    assert xrc.loadpanic == 88.9
    xrc.cpucheck(" 14:39:37 up 162 days, 20:14, 34 users,  load average: 0.81, 0.65, 0.63")
    assert xrc.xload == 0.65
    assert xrc.xuptime == 162 * DAY_M + 20 * 60 + 14
    xrc.cpucheck(" 14:39:37 up 162 days, 00:14, 34 users,  load average: 4.81, 4.65, 4.63")
    assert xrc.xload == 4.65
    assert xrc.xuptime == 162 * DAY_M + 14
    xrc.cpucheck(" 14:39:37 up 162 mins, 34 users,  load average: 4.81, 4.65, 4.63")
    assert xrc.xuptime == 162
    #xrc.cpucheck(" 4:45pm up 554.61 hours, 34 users,  load average: 4.81, 4.65, 4.63")
    #assert xrc.xuptime == 162
    xrc.cpucheck(" 21:39:37 up 162 days, 22min, 34 users,  load average: 4.81, 4.65, 4.63")
    assert xrc.xuptime == 162 * DAY_M + 22
    xrc.cpucheck(" 7:39AM up 162 days, 22min, 34 users,  load average: 4.81, 4.65, 4.63")
    assert xrc.xuptime == 162 * DAY_M + 22
    ret = xrc.cpucheck(" 7:39AM up 162 days 22:44, 34 users,  load average: 4.81, 4.65, 4.63")
    assert xrc.xuptime == 162 * DAY_M + 22 * 60 + 44
    assert ret["UP"]["color"] == 'green'
    ret = xrc.cpucheck(" 7:39AM up 10 mins, 34 users,  load average: 4.81, 4.65, 4.63")
    assert xrc.xuptime == 10
    assert ret["UP"]["color"] == 'yellow'
    # synologie
    ret = xrc.cpucheck(" 09:26:10 up 25 days, 19:15,  1 user,  load average: 0.00, 0.07, 0.06 [IO: 0.00, 0.01, 0.05 CPU: 0.00, 0.05, 0.05")
    # OPNsense
    ret = xrc.cpucheck(" 9:27AM  up 389 days, 23:32, 1 user, load averages: 0.19, 0.14, 0.09")


def test_setcolor():
    assert setcolor('red', 'green') == 'red'
    assert setcolor('red', 'yellow') == 'red'
    assert setcolor('green', 'red') == 'red'
    assert setcolor('green', 'yellow') == 'yellow'
    assert setcolor('green', 'clear') == 'green'
    assert setcolor('yellow', 'clear') == 'yellow'
    assert setcolor('red', 'clear') == 'red'

def test_xydhm():
    assert xydhm(0, 3600) == '1h'
    assert xydhm(0, 60) == '1m'
    assert xydhm(0, 60 * 60 * 24) == '1d'
    assert xydhm(0, 70 * 60) == '1h 10m'
    assert xydhm(0, 60 * 60 * 24 + 10 * 60) == '1d 10m'
    assert xydhm(0, 60 * 60 * 24 + 10 * 60 * 60) == '1d 10h'

def test_replace():
    X = xythonsrv()
    X.etcdir = './tests/etc/xymon/'
    X.debug = True
    X.debugs = ['vars']
    buf = X.xymon_replace("$SHELL")
    assert buf == '/bin/sh'
    buf = X.xymon_replace("$DONOTEXIST")
    assert buf == ''
