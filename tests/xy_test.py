#!/usr/bin/env python3

import os
import pytest
import random
import re
import shutil
import subprocess
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
from xython.common import xyevent
from xython.common import xyevent_to_ts
from xython.common import event_thisyear
from xython.common import event_lastyear
from xython.common import event_thismonth
from xython.common import event_lastmonth
from xython.common import event_thisweek
from xython.common import event_lastweek
from xython.common import event_yesterday
from xython.common import event_today
from xython.common import setcolor
from xython.common import is_valid_hostname
from xython.common import is_valid_column
from xython.rules import xy_rule_disks
from xython.rules import xy_rule_port
from xython.rules import xy_rule_proc
from xython.rules import xy_rule_mem
from xython.rules import xy_rule_cpu
from xython.rules import xy_rule_sensors
from xython.xython import xythonsrv
from xython.xython_tests import hex_to_binary
from xython.xython_tests import hex_compare
from xython.xython_tests import ping
from xython.xython_tests import dohttp
from xython.xython_tests import do_generic_proto

try:
    import rrdtool
    has_rrdtool = True
except ImportError:
    has_rrdtool = False

def setup_testdir(X, name):
    X.xt_data = f'./tests/data-{name}-' + str(random.randint(0, 32000))
    X.xt_logdir = f'{X.xt_data}/logs/'
    if not os.path.exists(X.xt_data):
        os.mkdir(X.xt_data)
    if not os.path.exists(X.xt_logdir):
        os.mkdir(X.xt_logdir)

def test_xytime():
    assert xytime(1678871776) == 'Wed Mar 15 10:16:16 2023'
    assert xyts('Wed Mar 15 10:16:16 2023', 'CET') == 1678871776
    assert xyts_('Wed_Mar_15_10:16:16_2023', 'CET') == 1678871776
    assert xytime(1328630692) == 'Tue Feb 7 17:04:52 2012'
    assert xytime_(1328630692) == 'Tue_Feb_7_17:04:52_2012'
    assert xyts_('Tue_Feb_7_17:04:52_2012', 'CET') == 1328630692
    assert xyts('Tue Feb 7 17:04:52 2012', 'CET') == 1328630692
    assert xyevent(1702846434) == '2023/12/17@21:53:54'
    assert xyevent_to_ts("2023/12/17@21:53:54", 'CET') == 1702846434
    assert xyevent_to_ts("2023/12/17@21:53:54", 'Europe/Paris') == 1702849494
    assert event_thisyear(1702846434) == '2023/01/01@00:00:00'
    assert event_lastyear(1702846434) == '2022/01/01@00:00:00'
    assert event_thismonth(1702846434) == '2023/12/01@00:00:00'
    assert event_lastmonth(1702846434) == '2023/11/01@00:00:00'
    # 1672828414 is 2023 01 day=04 week=wed
    assert event_lastmonth(1672828414) == '2022/12/01@00:00:00'
    assert event_thisweek(1672828414) == '2023/01/02@00:00:00'
    assert event_lastweek(1672828414) == '2022/12/26@00:00:00'
    assert event_yesterday(1672828414) == '2023/01/03@00:00:00'
    assert event_today(1672828414) == '2023/01/04@00:00:00'


def test_git():
    now = time.time()
    assert gif("red", now) == 'red-recent.gif'
    assert gif("red", now - 300) == 'red.gif'
    assert gif("red", now, False) == 'red-recent.gif'
    assert gif("red", now, True) == 'red-ack.gif'
    assert gif("-", now) == 'unknown-recent.gif'


def test_color():
    assert gcolor("pu") == 'purple'
    assert gcolor("re") == 'red'
    assert gcolor("ye") == 'yellow'
    assert gcolor("gr") == 'green'
    assert gcolor("bl") == 'blue'
    assert gcolor("cl") == 'clear'
    assert gcolor("plop") == 'purple'
    assert gcolor("-") == 'unknown'


def test_tokenize1():
    tok = tokenize('LOCAL=:22 state=LISTEN TEXT=SSH')
    assert len(tok) == 3


def test_tokenize2():
    tok = tokenize('LOCAL=%[.:]5500$ STATE=LISTEN "TEXT=SSH listener"')
    assert len(tok) == 3
    tok = tokenize('LOCAL=%[.:]22$ STATE= "LISTEN" "TEXT=SSH listener"')
    assert len(tok) == 3


def test_validator():
    assert is_valid_hostname("test")
    assert is_valid_hostname("test46")
    assert is_valid_hostname("test_46")
    assert is_valid_hostname("test-46")
    assert not is_valid_hostname("test,")
    assert not is_valid_hostname("test=")
    assert not is_valid_hostname("^test")
    assert not is_valid_hostname("test+")
    assert not is_valid_hostname("test/")
    assert not is_valid_hostname("test*")
    assert not is_valid_hostname("teséàçö")
    assert is_valid_column("test")
    assert is_valid_column("test46")
    assert is_valid_column("test_46")
    assert is_valid_column("test-46")
    assert not is_valid_column("test,")
    assert not is_valid_column("test=")
    assert not is_valid_column("^test")
    assert not is_valid_column("test+")
    assert not is_valid_column("test/")
    assert not is_valid_column("test*")
    assert not is_valid_column("teséàçö")


def test_read_xymonserver():
    X = xythonsrv()
    X.etcdir = './tests/invalid/'
    setup_testdir(X, 'xymonserver')

    ret = X.load_xymonserver_cfg()
    assert ret == X.RET_ERR
    X.etcdir = './tests/bogus/'
    ret = X.load_xymonserver_cfg()
    assert ret == X.RET_OK

    shutil.rmtree(X.xt_data)

def test_xython_getvar():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'xythongetvar')

    X.load_xymonserver_cfg()
    assert X.xython_getvar("UNSET") is None
    assert X.xython_getvar("") is None
    assert X.xython_getvar("XYTHON_TLS_KEY") == "./etc/xython/xymon.montjoie.local.key"

    shutil.rmtree(X.xt_data)

def test_xymon_getvar():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'xymongetvar')

    X.lldebug = True
    X.load_xymonserver_cfg()
    assert X.xymon_getvar("UNSET") == ""
    assert X.xymon_getvar("") == ""
    assert X.xymon_getvar("SHELL") == "/bin/sh"
    assert X.xymon_getvar("XYMONVAR") == "./tests/xymonvar"
    assert X.xymon_getvar("XYMONHISTDIR") == "./tests/xymonvar/hist"
    X.set_xymonvar("./tests/xymonvar2")
    assert X.xymon_getvar("XYMONVAR") == "./tests/xymonvar2"

    shutil.rmtree(X.xt_data)

def test_port_rule():
    rp = xy_rule_port()
    rp.init_from('LOCAL=:22 state=LISTEN TEXT=SSH')
    assert rp.local == ':22'
    assert rp.state == 'LISTEN'
    assert rp.rstate == None
    assert rp.text == 'SSH'

    rp = xy_rule_port()
    rp.init_from('LOCAL=%:22 state=LISTEN TEXT=SSH')
    assert rp.local == ':22'
    assert rp.state == 'LISTEN'
    assert rp.rstate == None
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

def test_ss_netstat():
    rp = xy_rule_port()
    rp.init_from('LOCAL=%:2049 state=LISTEN TEXT=NFS')
    rp631 = xy_rule_port()
    rp631.init_from('LOCAL=%:631 state=LISTEN TEXT=CUPS')

    f = open("./tests/ports/ss")
    data = f.readlines()
    f.close()
    rp.check(data)
    assert rp._count == 1
    rp631.check(data)
    assert rp631._count == 2

    f = open("./tests/ports/netstat")
    data = f.readlines()
    f.close()
    rp.check(data)
    assert rp._count == 1
    rp631.check(data)
    assert rp631._count == 2

def test_port_check():
    f = open("./tests/ports/1678699830")
    data = f.readlines()
    f.close()
    rp = xy_rule_port()
    rp.init_from('LOCAL=%:22 state=LISTEN TEXT=SSH')
    rp.check(data)
    assert rp._count == 2

    rp = xy_rule_port()
    rp.init_from('LOCAL=:69 TEXT=TFTP')
    rp.check(data)
    assert rp._count == 2

    rp = xy_rule_port()
    rp.init_from('LOCAL=0.0.0.0:69 TEXT=TFTP')
    rp.check(data)
    assert rp._count == 1

    rp = xy_rule_port()
    rp.init_from('LOCAL=0.0.0.0:69 state=LISTEN TEXT=TFTP')
    rp.check(data)
    assert rp._count == 0

    rp = xy_rule_port()
    rp.init_from('LOCAL=:111 state=LISTEN TEXT=NFS')
    rp.check(data)
    assert rp._count == 2

    rp = xy_rule_port()
    rp.init_from('LOCAL=:111 TEXT=NFS2')
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
    #with pytest.raises(SystemExit):
    assert xydelay('60x') == None
    assert xydelay('test') == None
    assert xydelay('tesh') == None


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
    assert ret is not None
    assert xrc.xuptime == 389 * DAY_M + 23 * 60 + 32
    # libreELEC
    ret = xrc.cpucheck(" 16:40:58 up 26 min,  load average: 0.72, 0.61, 0.48")
    assert ret is not None
    assert xrc.xuptime == 26
    # OpenBSD 7.4
    # no up for the first minute
    ret = xrc.cpucheck(" 9:09PM  26 secs, 0 users, load averages: 0.33, 0.09, 0.03")
    assert ret is not None
    assert xrc.xuptime == 0


def test_setcolor():
    assert setcolor('red', 'green') == 'red'
    assert setcolor('red', 'yellow') == 'red'
    assert setcolor('green', 'red') == 'red'
    assert setcolor('green', 'yellow') == 'yellow'
    assert setcolor('green', 'clear') == 'green'
    assert setcolor('yellow', 'clear') == 'yellow'
    assert setcolor('red', 'clear') == 'red'

def test_xydhm():
    assert xydhm(0, 36) == '0m'
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
    #buf = X.xymon_replace("$SHELL")
    #assert buf == '/bin/sh'
    #buf = X.xymon_replace("$DONOTEXIST")
    #assert buf == ''

def test_lmsensors():
    f = open("./tests/sensors/sensors1")
    data = f.read()
    f.close()
    xs = xy_rule_sensors()
    xs.add("%.* %.*  20 30")
    #assert xs.warn == 30
    #assert xs.panic == 30
    print(xs.rules)
    assert xs.is_sensor("") == None
    assert xs.is_sensor("Adapter: fake") == None
    assert xs.is_sensor("Adapter: 40 RPM") == None
    assert xs.is_sensor("in0 30") == None
    assert xs.is_sensor("in0: 30") == None
    assert xs.is_sensor("in0: 30 V") is not None
    assert xs.is_sensor("in0: 30 mV") is not None
    assert xs.is_sensor("in0: 30 RPM") is not None
    ret = xs.is_sensor("in0: +30°C")
    assert ret is not None
    assert len(ret) == 3
    assert ret[0] == 'in0'
    assert ret[1] == '30'
    assert ret[2] == 'C'
    ret = xs.is_sensor("fan7: 4500 RPM")
    assert ret is not None
    assert len(ret) == 3
    assert ret[0] == 'fan7'
    assert ret[1] == '4500'
    assert ret[2] == 'RPM'


    ret = xs.is_sensor("CPU temperature: +30°C")
    assert ret is not None
    assert len(ret) == 3
    assert ret[0] == 'CPU temperature'
    assert ret[1] == '30'
    assert ret[2] == 'C'

    ret = xs.check("fake", "in0: +40.7°C")
    assert ret["color"] == 'red'
    xs.add("%.* in0 50 60")
    ret = xs.check("fake", "in0: +40.7°C")
    assert ret["color"] == 'green'
    ret = xs.check("fake", "temp0: +40.7°C")
    assert ret["color"] == 'red'

    xs = xy_rule_sensors()
    xs.add("DEFAULT C 20 30 0 -10")
    ret = xs.check("fake2", "temp0: -40.7°C")
    assert ret["color"] == 'red'
    ret = xs.check("fake2", "temp0: -5.7°C")
    assert ret["color"] == 'yellow'
    xs.add('%.* "SENSOR SPACE"  20 30')
    ret = xs.check("fake2", "SENSOR SPACE: 40°C")
    assert ret["color"] == 'red'
    xs.add('%.* AUXTIN -29 -28 -30 -31')
    ret = xs.check("fake2", "AUXTIN:         -29.5 C  (high = +80.0 C, hyst = +75.0 C)  sensor = thermistor")
    assert ret["color"] == 'green'

    # test ignore
    xs = xy_rule_sensors()
    xs.add("DEFAULT C 20 30 0 -10")
    ret = xs.check("fake2", "temp0: -40.7°C")
    assert ret["color"] == 'red'
    xs.add("fake2 temp0 IGNORE")
    print(xs.rules)
    ret = xs.check("fake2", "temp0: -40.7°C")
    assert ret["color"] == 'clear'
    ret = xs.check("fake2", "temp1: -40.7°C")
    assert ret["color"] == 'red'
    # TODO ignore whole adapter
    # xs.add("fake2 IGNORE")
    # ret = xs.check("fake2", "temp1: -40.7°C")
    # assert ret["color"] == 'clear'

def test_reload():
    # we should have 2 hosts with conn on each
    # test that conn is added by default
    with open("./tests/etc/xython-load/hosts.cfg", 'w') as f:
        f.write("192.168.1.40	test01		#conn\n\
2a01:cb1d:3d5:a100:4a02:2aff:fe07:1efc  ipv6\n")
    X = xythonsrv()
    X.etcdir = './tests/etc/xython-load/'
    setup_testdir(X, 'load')
    X.init()
    X.read_configs()
    H = X.find_host("donotexists")
    assert H is None
    H = X.find_host("ipv6")
    assert H is not None
    assert len(X.xy_hosts) == 2
    res = X.sqc.execute(f'SELECT * FROM tests')
    results = X.sqc.fetchall()
    #print(results)
    assert len(results) == 2

    # we should have 3 hosts with conn on each except for ipv6
    # test that conn is removed from ipv6
    #time.sleep(1)
    with open("./tests/etc/xython-load/hosts.cfg", 'w') as f:
        f.write("192.168.1.40	test01		#conn\n\
192.168.1.45	test02		#conn\n\
2a01:cb1d:3d5:a100:4a02:2aff:fe07:1efc	ipv6 # noconn\n")
    X.read_configs()
    assert len(X.xy_hosts) == 3
    res = X.sqc.execute(f'SELECT * FROM tests')
    results = X.sqc.fetchall()
    #print(results)
    assert len(results) == 2
    assert len(X.xy_hosts) == 3

    # we should have 2 hosts with conn on each except for ipv6
    # test that test02 is removed
    with open("./tests/etc/xython-load/hosts.cfg", 'w') as f:
        f.write("192.168.1.40	test01		#conn\n\
2a01:cb1d:3d5:a100:4a02:2aff:fe07:1efc	ipv6 # noconn\n")
    X.read_configs()
    assert len(X.xy_hosts) == 2
    res = X.sqc.execute(f'SELECT * FROM tests')
    results = X.sqc.fetchall()
    #print(results)
    assert len(results) == 1
    assert len(X.xy_hosts) == 2

    # backup to have a clean git diff
    # TODO find better
    with open("./tests/etc/xython-load/hosts.cfg") as f:
        bh = f.read()
    with open("./tests/etc/xython-load/analysis.cfg") as f:
        ba = f.read()

    with open("./tests/etc/xython-load/hosts.cfg", "a") as f:
        f.write("0.0.0.0 test0\n")
    with open("./tests/etc/xython-load/analysis.cfg", "a") as f:
        f.write("HOST=test0\n\tPROC test\n")
    X.read_configs()
    # verify new hosts is detected
    H = X.find_host("test0")
    assert H is not None
    with open("./tests/etc/xython-load/analysis.cfg", "a") as f:
        f.write("\tPROC test2\n")
    X.read_configs()
    H = X.find_host("test0")
    assert H is not None
    # verify PROC rules are correctly reseted
    assert len(H.rules["PROC"]) == 2

    with open("./tests/etc/xython-load/hosts.cfg", "w") as f:
        f.write(bh)
    with open("./tests/etc/xython-load/analysis.cfg", "w") as f:
        f.write(ba)

    print("==========================")
    print("snmp.d creation")
    os.mkdir("./tests/etc/xython-load/snmp.d")
    ret = X.read_hosts()
    assert ret == X.RET_NEW
    print(X.mtimes_hosts)
    assert "./tests/etc/xython-load/snmp.d" in X.mtimes_hosts
    assert X.mtimes_hosts["./tests/etc/xython-load/snmp.d"]["mtime"] > 0

    ret = X.read_hosts()
    assert ret == X.RET_OK
    os.rmdir('./tests/etc/xython-load/snmp.d')

    X.sqc.close()
    os.remove(f"{X.xt_data}/xython.db")
    shutil.rmtree(X.xt_data)

def test_protocols_binary():
    assert hex_to_binary('\\x35\\x36') == b'56'
    assert hex_to_binary('\\x35\\x37') == b'57'
    assert hex_to_binary('\\x35\\x37GET') == b'57GET'
    assert hex_to_binary('\\x35\\o') is None
    assert hex_to_binary('\\') is None
    assert hex_to_binary('\\x1') is None
    assert hex_to_binary('\\r\\t\\n') == bytes.fromhex("0D 09 0A")
    assert hex_to_binary('\\r\\t\\n') == '\r\t\n'.encode("UTF8")
    assert hex_compare(b'67', '\\x36\\x37')
    assert hex_compare(b'ABC', '\\x41\\x42\\x43')
    assert not hex_compare(b'ABC', '\\x41\\x42\\x44')
    assert not hex_compare(b'ABC', '\\x41\\x3778899')
    assert not hex_compare(b'ABC', '\\x414')

def test_full():
    X = xythonsrv()
    X.lldebug = True
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'full')
    X.wwwdir = './tests/www/'
    X.init()
    # TODO set webdir in config file
    X.webdir = './xymon/web/'
    X.read_configs()
    H = X.find_host("donotexists")
    assert H is None
    H = X.find_host("test2")
    assert H is not None
    assert 'ftp' in H.tags

    H = X.find_host("test15bis")
    assert H is not None
    assert H.name == "test15"
    H = X.find_host("xy")
    assert H is not None
    assert H.name == "test16"

    # no testip
    H = X.find_host("test3")
    assert H.gethost() == 'test3'
    # with testip
    H = X.find_host("test4")
    assert H.gethost() == '1.1.1.4'
    # we should not have any column other than info
    lc = X.get_columns("test3")
    assert lc == ['info']

    assert X.xt_rrd == f'{X.xt_data}/rrd/'
    X.do_rrd("test1", "test", "t", "t", 444, "DS:t:GAUGE:600:-280:5000")
    if has_rrdtool:
        rrdfpath = f"{X.xt_rrd}/test1/test.t.rrd"
        info = rrdtool.info(rrdfpath)
        assert info
        X.gen_rrds()
        X.gen_rrd('test1')

    X.unixsock = './tests/run/xython.sock'
    assert X.unet_start()
    X.unet_send("status+10m test1.coltest red\nfake content\n")
    X.unet_loop()
    res = X.sqc.execute(f'SELECT * FROM columns where column == "coltest"')
    results = X.sqc.fetchall()
    assert len(results) == 1

    X.unet_send("acknowledge test1.coltest 60m test")
    X.unet_loop()

    # TODO verify content
    X.gen_html("nongreen", None, None, None)
    X.gen_html("all", None, None, None)
    X.gen_html("svcstatus", None, None, None)
    X.gen_html("svcstatus", "test1", "coltest", 0)
    # TODO get the right ts for svcstatus

    # send ack for coltest

    # send bogus ack
    X.unet_send("acknowledge invalid.coltest 60m test")
    X.unet_loop()
    X.unet_send("acknowledge invalid.invalid 60m test")
    X.unet_loop()
    X.unet_send("acknowledge test1.invalid 60m test")
    X.unet_loop()

    # test disable
    X.unet_send("disable test1.coltest 60m test")
    X.unet_loop()
    X.unet_send("disable invalid.coltest 60m test")
    X.unet_loop()
    X.unet_send("disable invalid.invalid 60m test")
    X.unet_loop()
    X.unet_send("disable test1.invalid 60m test")
    X.unet_loop()

    # call the scheduler
    X.scheduler()
    # TODO find something that should changed after this call

    # test client data
    f = open("./tests/clientdata/good0")
    data = f.read()
    f.close()

    X.unet_send(f"proxy: test\n{data}")
    X.unet_loop()
    res = X.sqc.execute(f'SELECT * FROM columns where hostname == "test1"')
    results = X.sqc.fetchall()
    # TODO check each column (disk, cpu, etc..) exists
    expected_cols = ['disk', 'cpu', 'coltest', 'info', 'inode', 'memory', 'ports', 'procs', 'sensor']
    if has_rrdtool:
        expected_cols.append('xrrd')
    assert len(results) == len(expected_cols)

    # test client data with bogus
    f = open("./tests/clientdata/bogus")
    data = f.read()
    f.close()

    X.unet_send(f"proxy: test\n{data}")
    X.unet_loop()
    shutil.rmtree(X.xt_data)

def test_snmpd():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'snmpd')
    X.daemon_name = "xython-snmpd"
    X.init()
    X.read_hosts()
    X.hosts_check_tags()
    # test community
    #do_snmpd(X)
    shutil.rmtree(X.xt_data)

def test_snmpd2():
    X = xythonsrv()
    X.etcdir = './tests/etc/snmp/'
    setup_testdir(X, 'snmpd2')
    X.daemon_name = "xython-snmpd"
    X.init()
    X.read_hosts()
    X.hosts_check_tags()
    # test community
    #do_snmpd(X)
    shutil.rmtree(X.xt_data)

def test_tests():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'tests')
    X.init()
    X.read_hosts()
    X.dump_tests()
    X.gen_tests()
#    X.do_tests()
    shutil.rmtree(X.xt_data)

def test_rrd():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'rrd')
    X.lldebug = True
    X.init()
    X.read_hosts()
    # test the truncating
    assert X.rrd_getdsname("01234567890123456789") == "0123456789012345678"
    # test space replacement
    assert X.rrd_getdsname("one test") == "one_test"
    assert X.rrd_pathname("disk", '/') == "disk,root"
    assert X.rrd_pathname("disk", '/test') == "disk,test"
    ret = X.gen_cgi_rrd("test3", "invalid", "unused")
    assert ret == 'Status: 400 Bad Request\n\nERROR: invalid not found in graphs.cfg'
    ret = X.gen_cgi_rrd("test3", "memory", "unused")
    assert ret == f'Status: 400 Bad Request\n\nERROR: {X.xt_data}/rrd//test3 not found'
    # following test could not work without rrdtool
    if not has_rrdtool:
        shutil.rmtree(X.xt_data)
        return
    X.do_rrd("test3", 'la', 'la', 'la', 4, ['DS:la:GAUGE:600:0:U'])
    # now test3 directory exists
    ret = X.gen_cgi_rrd("test3", "memory", "unused")
    assert ret == 'Status: 400 Bad Request\n\nERROR: RRD list is empty'
    ret = X.gen_cgi_rrd("test3", "la", "unused")
    assert len(ret) > 23
    buf = ret[0:23]
    assert 'Content-type: image/png' == buf.decode('UTF8')
    # TODO check we have a real image
    X.do_sensor_rrd("test3", "fakeadapter", "temp1", 42)
    ret = X.gen_cgi_rrd("test3", "sensor", "unused")
    assert len(ret) > 23
    buf = ret[0:23]
    assert 'Content-type: image/png' == buf.decode('UTF8')

    # now test the unix sock
    X.unixsock = './tests/run/xython.sock'
    assert X.unet_start()
    ret = X.unet_send_recv("GETRRD test3\n")
    assert ret == b'Status: 400 Bad Request\n\nERROR: not enough arguments'
    ret = X.unet_send_recv("GETRRD test3 memory\n")
    assert ret == b'Status: 400 Bad Request\n\nERROR: not enough arguments'
    ret = X.unet_send_recv("GETRRD test3 la view\n")
    assert len(ret) > 23
    buf = ret[0:23]
    assert 'Content-type: image/png' == buf.decode('UTF8')
    ret = X.unet_send_recv("GETRRD test3 sensor view\n")
    assert len(ret) > 23
    buf = ret[0:23]
    assert 'Content-type: image/png' == buf.decode('UTF8')
    # now test the CGI

    ret = subprocess.run('./xython/showgraph.py', capture_output=True, env=None)
    print(ret)
    assert ret.stdout == b'Status: 400 Bad Request\n\n\n\nno hostname\n\n'

    envi = {}
    envi['QUERY_STRING'] = 'hostname=invalid'
    ret = subprocess.run(['./xython/showgraph.py'], capture_output=True, env=envi)
    print(ret)
    assert ret.stdout == b'Status: 400 Bad Request\n\n\n\nno service\n\n'

    envi['QUERY_STRING'] = f'hostname=invalid&service=invalid&sockpath={X.unixsock}'
    ret = subprocess.run(['./xython/showgraph.py'], capture_output=True, env=envi)
    print(ret)
    assert ret.stdout == b'Status: 500 Internal Server Error\n\n\nshowgraph: FAIL to connect to xythond\n'

    envi['QUERY_STRING'] = 'hostname=invalid&service='
    ret = subprocess.run(['./xython/showgraph.py'], capture_output=True, env=envi)
    print(ret)
    assert ret.stdout == b'Status: 500 Internal Server Error\n\n\nshowgraph: FAIL to connect to xythond\n'

    shutil.rmtree(X.xt_data)

def test_celery_ping():
    ret = ping("test", "-invalid", False, False)
    assert ret["color"] == 'red'
    ret = ping("test", "-invalid", True, True)
    assert ret["color"] == 'red'

    test_ping = True
    # on github ping do not work
    # so do not check result if ping do not work, but still run it to at least catch some possible unhandled exceptions
    if 'GITHUB_ACTION' in os.environ:
        print("INFO: on github testing ping is disabled")
        test_ping = False
    ret = ping("test", "8.8.8.8", False, False)
    print(ret)
    if test_ping:
        assert ret["color"] == 'green'
    ret = ping("test", "8.8.8.8", True, False)
    if test_ping:
        assert ret["color"] == 'green'
    ret = ping("test", "google.com", True, True)
    if test_ping:
        assert ret["color"] == 'green'

@pytest.mark.filterwarnings("ignore:InsecureRequestWarning.*Unverified HTTPS.*")
def test_celery_http():
    ret = dohttp("test", ['https://selfsigned.xython.fr'], 'http')
    err = re.search("self-signed certificate", ret['txt'])
    assert ret["color"] == 'red'
    assert err
    ret = dohttp("test", ['https://selfsigned.xython.fr;verify=0'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://selfsigned.xython.fr;verify=1'], 'http')
    assert ret["color"] == 'red'

    ret = dohttp("test", ['https://customca.xython.fr'], 'http')
    err = re.search("unable to get local issuer certificate", ret['txt'])
    assert ret["color"] == 'red'
    assert err

    ret = dohttp("test", ['https://customca.xython.fr;verify=./tests/customca.xython.fr.ca'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.200', 'https://tests.xython.fr/test.403;httpcode=403'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont;cont=hello'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont.regex;cont=A[[:space:]]B'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont.regex;cont=new\nline'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont.regex;cont=\\x41\\x20\\x42'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont.regex;cont=\\x41\\x20\\x43'], 'http')
    assert ret["color"] == 'red'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont;cont=invalid'], 'http')
    assert ret["color"] == 'red'
    ret = dohttp("test", ['https://tests.xython.fr/test.cont;invalid=hello'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://tests.xython.fr/test.403;httpcode=200'], 'http')
    assert ret["color"] == 'red'

    ret = dohttp("test", ['https://google.com/'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://github.com/'], 'http')
    assert ret["color"] == 'green'
    ret = dohttp("test", ['https://www.xython.fr/'], 'http')
    print(ret)
    assert ret["color"] == 'green'

    # connexion refused
    ret = dohttp("test", ['https://tests.xython.fr:444/'], 'http')
    err = re.search("Connection refused", ret['txt'])
    assert ret["color"] == 'red'
    assert err
    ret = dohttp("test", ['http://tests.xython.fr:444/'], 'http')
    err = re.search("Connection refused", ret['txt'])
    assert ret["color"] == 'red'
    assert err
    # timeout
    ret = dohttp("test", ['http://8.8.8.8:445/;timeout=1'], 'http')
    assert ret["color"] == 'red'

def test_celery_protocols():
    # protocols test
    # no TLS tests
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldap'], None, None, None)
    assert ret["color"] == 'green'
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 444, ['ldap'], None, None, None)
    assert ret["color"] == 'red'
    err = re.search("Connection refused", ret['txt'])
    assert err
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', None, ['ldap:444'], None, None, None)
    print(ret)
    assert ret["color"] == 'red'
    err = re.search("Connection refused", ret['txt'])
    assert err
    ret = do_generic_proto("test", "tests.xython.fr", 'smtps', 587, ['smtp'], "ehlo xymonnet\r\nquit\r\n", "220", "banner")
    assert ret["color"] == 'green'
    ret = do_generic_proto("test", "tests.xython.fr", 'smtps', 587, ['smtp'], "ehlo xymonnet\r\nquit\r\n", "invalid220", "banner")
    assert ret["color"] == 'red'
    # send GET /
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldap'], "\\x47\\x45\\x54\\x20\\x2F\\x10\\x08\\x10\\x08", "\\x48\\x54\\x54\\x50", "banner")
    assert ret["color"] == 'green'
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldap'], "\\x47\\x45\\x54\\x20\\x2F\\x10\\x08\\x10\\x08", "\\x48\\x54\\x54\\x54", "banner")
    assert ret["color"] == 'red'

    # TLS tests
    ret = do_generic_proto("test", "tests.xython.fr", 'ldaps', 443, ['ldaps:hostname=tests.xython.fr'], None, None, "ssl")
    assert ret["color"] == 'green'
    # same with 2 hostname
    ret = do_generic_proto("test", "tests.xython.fr", 'ldaps', 443, ['ldaps:hostname=tests.xython.fr', 'ldaps:hostname=invalid'], None, None, "ssl")
    assert ret["color"] == 'red'
    err = re.search("CERTIFICATE_VERIFY_FAILED", ret['txt'])
    assert err
    ret = do_generic_proto("test", "tests.xython.fr", 'smtps', 465, ['smtps:verify=0'], "ehlo xymonnet\r\nquit\r\n", "220", "ssl, banner")
    assert ret["color"] == 'green'
    ret = do_generic_proto("test", "tests.xython.fr", 'smtps', 465, ['smtps:verify=0'], "ehlo xymonnet\r\nquit\r\n", "invalid220", "ssl, banner")
    assert ret["color"] == 'red'

    # test TLS hexa bad banner
    ret = do_generic_proto("test", "tests.xython.fr", 'ldaps', 443, ['smtps:443'], "\\x20ehlo xymonnet\r\nquit\r\n", "invalid220", "ssl, banner")
    assert ret["color"] == 'red'

    print("=====================================================")
    print("DEBUG: tests: try to connect to a closed port")
    ret = do_generic_proto("test", "tests.xython.fr", 'ldaps', 444, ['ldaps:hostname=tests.xython.fr'], None, None, "ssl")
    assert ret["color"] == 'red'
    err = re.search("Connection refused", ret['txt'])
    assert err
    ret = do_generic_proto("test", "tests.xython.fr", 'ldaps:444', None, ['ldaps:hostname=tests.xython.fr'], None, None, "ssl")
    assert ret["color"] == 'red'
    err = re.search("Connection refused", ret['txt'])
    assert err

    print("DEBUG: tests: send GET / and expect to find HTTP")
    #ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldaps:hostname=tests.xython.fr'], "GET /\\r\\nHTTP/1.1\\r\\nHost: test.xython.fr\\x13\\x10\\r\\n", "\\x48\\x54\\x54\\x50", "banner, ssl")
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldaps:hostname=tests.xython.fr'], "\\x47\\x45\\x54\\x20\\x2F\\x47HTTP/1.1\\x13\\x10Host: test.xython.fr\\x13\\x10\\r\\n", "\\x48\\x54\\x54\\x50", "banner, ssl")
    assert ret["color"] == 'green'

def test_net():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'net')
    assert not X.set_netport(0)
    assert not X.set_netport(100000)
    assert X.set_netport(1000)
    assert X.netport == 1000

    X.init()
    X.unixsock = './tests/run/xython.sock'
    assert X.unet_start()
    assert X.unet_start()
    shutil.rmtree(X.xt_data)

def test_misc():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'misc')
    X.init()
    X.print()
    shutil.rmtree(X.xt_data)

def test_clientlocal():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'misc')
    X.init()
    X.load_client_local_cfg()

    ret = X.parse_collector("")
    assert ret is None
    ret = X.parse_collector("[collector:]")
    assert ret is None
    # we should have an hostname
    ret = X.parse_collector("[collector:]\nclient ")
    assert ret is None
    # we should have host.ostype
    ret = X.parse_collector("[collector:]\nclient hostname")
    assert ret is None
    # test without class
    ret = X.parse_collector("[collector:]\nclient hostname.linux")
    assert ret == ["hostname", "linux", None]
    # test with class
    ret = X.parse_collector("[collector:]\nclient hostname.linux class")
    assert ret == ["hostname", "linux", "class"]
    # test handling of fqdn with dots
    ret = X.parse_collector("[collector:]\nclient fqdn.hostname.linux class")
    assert ret == ["fqdn.hostname", "linux", "class"]
    ret = X.parse_collector("[collector:]\nclient fqdn.hostname.linux class")
    assert ret == ["fqdn.hostname", "linux", "class"]

    ret = X.send_client_local("[collector:]\nclient fqdn.hostname.linux class")
    assert ret == ['log:/var/log/messages:10240', 'ignore MARK']
    # check priority of hostname
    ret = X.send_client_local("[collector:]\nclient test1.linux class")
    assert ret == ['datatest1']
    # check priority of class
    ret = X.send_client_local("[collector:]\nclient test4.linux test2")
    assert ret == ['data', 'test2']
    # test non-linux
    ret = X.send_client_local("client test4.freebsd test2")
    assert ret == ['data', 'test2']


    shutil.rmtree(X.xt_data)
