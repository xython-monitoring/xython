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
from xython.common import is_valid_color
from xython.common import is_valid_column
from xython.rules import xy_rule_disks
from xython.rules import xy_rule_port
from xython.rules import xy_rule_proc
from xython.rules import xy_rule_mem
from xython.rules import xy_rule_cpu
from xython.rules import xy_rule_sensors
from xython.xython import xythonsrv
from xython.xython import xy_host
from xython.xython_tests import hex_to_binary
from xython.xython_tests import hex_compare
from xython.xython_tests import ping
from xython.xython_tests import dohttp
from xython.xython_tests import do_generic_proto
from xython.xython_tests import xssh
from xython.xython_tests import snmp_get
from xython.xython_tests import do_generic_proto
from xython.xython_tests import do_snmpd_disk
from xython.xython_tests import do_snmpd_memory

try:
    import rrdtool
    has_rrdtool = True
except ImportError:
    has_rrdtool = False

DEFAULT_PING_TARGET = '8.8.8.8'
if 'PING_TARGET' in os.environ:
    DEFAULT_PING_TARGET = os.environ['PING_TARGET']

# being root breaks EPERM tests
assert os.getuid() != 0

def clean_html(hdir):
    dirFiles = os.listdir(hdir)
    print(f"========= CLEAN {hdir}")
    for file in dirFiles:
        if file == '.empty':
            continue
        print(f'HANDLE {file}')
        if 'html' in file or 'png' in file:
            os.remove(f'{hdir}/{file}')
            continue
        clean_html(f'{hdir}/{file}')
        os.rmdir(f'{hdir}/{file}')

def setup_testdir(X, name):
    X.xt_data = f'./tests/data-{name}-' + str(random.randint(0, 32000))
    X.xt_logdir = f'{X.xt_data}/logs/'
    if not os.path.exists(X.xt_data):
        os.mkdir(X.xt_data)
    if not os.path.exists(X.xt_logdir):
        os.mkdir(X.xt_logdir)
    wwwdir = 'tests/www/'
    if os.path.exists(wwwdir):
        clean_html(wwwdir)

def setup_clean(X):
    shutil.rmtree(X.xt_data)

    wwwdir = 'tests/www/'
    if os.path.exists(wwwdir):
        clean_html(wwwdir)

def test_xytime():
    assert xytime(1678871776) == 'Wed Mar 15 10:16:16 2023'
    assert xytime(1678871776, 'GMT') == 'Wed Mar 15 09:16:16 2023'
    assert xytime(1678871776, 'Europe/Paris') == 'Wed Mar 15 10:16:16 2023'
    assert xyts('Wed Mar 15 09:16:16 2023', 'GMT') == 1678871776
    assert xyts('Wed Mar 15 09:16:16 2023', 'utc') == 1678871776

    assert xyts('Wed Mar 15 10:16:16 2023', 'CET') == 1678871776
    assert xyts('Wed Mar 15 10:16:16 2023', 'Europe/Paris') == 1678871776

    assert xyts_('Wed_Mar_15_10:16:16_2023', 'CET') == 1678871776
    assert xyts_('Wed_Mar_15_10:16:16_2023', 'Europe/Paris') == 1678871776

    assert xytime(1328630692) == 'Tue Feb 7 17:04:52 2012'
    assert xytime_(1328630692) == 'Tue_Feb_7_17:04:52_2012'
    assert xyts_('Tue_Feb_7_17:04:52_2012', 'CET') == 1328630692
    assert xyts('Tue Feb 7 17:04:52 2012', 'CET') == 1328630692

    assert xyevent(1702846434) == '2023/12/17@21:53:54'
    assert xyevent_to_ts("2023/12/17@21:53:54", 'CET') == 1702846434
    assert xyevent_to_ts("2023/12/17@21:53:54", 'Europe/Paris') == 1702846434
    assert xyevent_to_ts("") is None
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
    assert is_valid_hostname("www.google.com")
    assert not is_valid_hostname("a b")
    assert not is_valid_hostname("invalid|")
    assert not is_valid_hostname("invalid*")
    assert not is_valid_hostname("invalid(")
    assert not is_valid_hostname("invalid)")
    assert not is_valid_hostname("invalid\\")
    assert not is_valid_hostname("invalid#")
    assert not is_valid_hostname("invalid.")
    assert not is_valid_hostname(".invalid")
    assert not is_valid_hostname("test,")
    assert not is_valid_hostname("test=")
    assert not is_valid_hostname("^test")
    assert not is_valid_hostname("test+")
    assert not is_valid_hostname("test/")
    assert not is_valid_hostname("test/test")
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
    assert not is_valid_color("teséàçö")
    assert is_valid_color("green")


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
    assert rp.rstate is None
    assert rp.text == 'SSH'

    rp = xy_rule_port()
    rp.init_from('LOCAL=%:22 state=LISTEN TEXT=SSH')
    assert rp.local == ':22'
    assert rp.state == 'LISTEN'
    assert rp.rstate is None
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


def test_disk():

    xrd = xy_rule_disks()
    assert xrd.add('/ 10 30')
    assert xrd.rules['/'].warn == 10
    assert xrd.rules['/'].panic == 30
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  90% /")
    assert ret["color"] == "red"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  10% /")
    assert ret["color"] == "yellow"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  0% /")
    assert ret["color"] == "green"

    xrd = xy_rule_disks()
    assert xrd.add('/ 98 99')
    assert xrd.add('%.* 90 95')
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
    # assert xrd.rules['/'].warn == 98
    # assert xrd.rules['/'].panic == 99
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  95% /")
    assert ret["color"] == "red"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  90% /")
    assert ret["color"] == "yellow"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  0% /")
    assert ret["color"] == "green"
    ret = xrd.check("/dev/root                          229640100  194555144  23347072  0 /")
    assert ret is None
    ret = xrd.check("/dev/mmcblk0p1                     0        0         0     - /boot/efi")
    assert ret is None


    X = xythonsrv()
    X.lldebug = True
    X.etcdir = './tests/etc/xython-load/'
    setup_testdir(X, 'disk')
    X.init()

    f = open("./tests/disk/test0")
    data = f.read()
    f.close()
    X.parse_df('test01', data, False, 'fake')
    X.sqc.execute('SELECT * FROM columns WHERE hostname == "test01" AND column == "disk"')
    results = X.sqc.fetchall()
    print(results)
    assert len(results) == 1
    result = results[0]
    assert result[4] == 'red'

    # test errors
    xrd = xy_rule_disks()
    assert not xrd.add('%.* 90')

    shutil.rmtree(X.xt_data)


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
    # with pytest.raises(SystemExit):
    assert xydelay('60x') is None
    assert xydelay('test') is None
    assert xydelay('tesh') is None


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
    # xrc.cpucheck(" 4:45pm up 554.61 hours, 34 users,  load average: 4.81, 4.65, 4.63")
    # assert xrc.xuptime == 162
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
    assert setcolor('clear', 'green') == 'green'
    assert setcolor('clear', 'yellow') == 'yellow'
    assert setcolor('clear', 'red') == 'red'


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
    # buf = X.xymon_replace("$SHELL")
    # assert buf == '/bin/sh'
    # buf = X.xymon_replace("$DONOTEXIST")
    # assert buf == ''


def test_lmsensors():
    # f = open("./tests/sensors/sensors1")
    # data = f.read()
    # f.close()
    xs = xy_rule_sensors()
    xs.add("%.* %.*  20 30")
    # assert xs.warn == 30
    # assert xs.panic == 30
    print(xs.rules)
    assert xs.is_sensor("") is None
    assert xs.is_sensor("Adapter: fake") is None
    assert xs.is_sensor("Adapter: 40 RPM") is None
    assert xs.is_sensor("in0 30") is None
    assert xs.is_sensor("in0: 30") is None
    assert xs.is_sensor("in0: 30 V") is not None
    assert xs.is_sensor("in0: 30 mV") is not None
    assert xs.is_sensor("in0: 30 RPM") is not None
    assert xs.is_sensor("pwm2: 26%  (mode = pwm)  MANUAL CONTROL") is not None
    assert xs.is_sensor("APSS 15 :  83.38 MJ") is not None
    assert xs.is_sensor("Chip 0 GPU:              141.01 MJ") is not None
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
    assert xs.add("DEFAULT C 20 30 0 -10")
    ret = xs.check("fake2", "temp0: -40.7°C")
    assert ret["color"] == 'red'
    assert xs.add("fake2 temp0 IGNORE")
    print(xs.rules)
    ret = xs.check("fake2", "temp0: -40.7°C")
    assert ret["color"] == 'clear'
    ret = xs.check("fake2", "temp1: -40.7°C")
    assert ret["color"] == 'red'
    # TODO ignore whole adapter
    # xs.add("fake2 IGNORE")
    # ret = xs.check("fake2", "temp1: -40.7°C")
    # assert ret["color"] == 'clear'

    # tests invalid lines
    assert not xs.add("")
    assert not xs.add("adapter")
    assert not xs.add("adapter temp")
    assert not xs.add("adapter temp A")

    X = xythonsrv()
    X.etcdir = './tests/etc/xython-load/'
    X.lldebug = True
    setup_testdir(X, 'sensors')
    X.init()

    f = open("./tests/sensors/sensors2")
    data = f.read()
    f.close()
    X.parse_sensors("test01", data, "fake")
    assert 'parsesensor' in X.stats

    f = open("./tests/sensors/sensors3")
    data = f.read()
    f.close()
    X.parse_sensors("test01", data, "fake")

    f = open("./tests/sensors/sensors4")
    data = f.read()
    f.close()
    X.parse_sensors("test01", data, "fake")

    print(X.stats["parsesensor"])
    setup_clean(X)

    X = xythonsrv()
    X.etcdir = './tests/etc/xython-sensors/'
    X.lldebug = True
    setup_testdir(X, 'sensors')
    X.init()

    X.parse_sensors("test01", data, "fake")

    f = open("./tests/sensors/sensors8")
    data8 = f.read()
    f.close()
    X.parse_sensors("test01", data8, "fake")
    res = X.sqc.execute('SELECT ts FROM columns WHERE hostname == "test01" AND column == "sensor"')
    results = X.sqc.fetchall()
    ts = results[0][0]
    d = X.get_histlogs("test01", "sensor", ts)
    raw = ''.join(d['raw'])
    assert 'yellow Chip 0 Vdd CHECK=(0.841 => 0.8)' in raw
    assert 'red APSS 14 CHECK=(104.14 => 30.0)' in raw
    assert 'yellow System CHECK=(226.0 <= MINWARN=1000.0)' in raw
    assert 'red APSS 0 CHECK=(865.94 <= MINPANIC=999.0)' in raw

    f = open("./tests/sensors/sensors5")
    data5 = f.read()
    f.close()
    X.parse_sensors("test01", data5, "fake")
    res = X.sqc.execute('SELECT ts FROM columns WHERE hostname == "test01" AND column == "sensor"')
    results = X.sqc.fetchall()
    ts = results[0][0]
    d = X.get_histlogs("test01", "sensor", ts)
    raw = ''.join(d['raw'])
    assert 'yellow pwm1 CHECK=(127.0 => 100.0)' in raw

    setup_clean(X)


def test_reload():
    # we should have 2 hosts with conn on each
    # test that conn is added by default
    with open("./tests/etc/xython-load/hosts.cfg", 'w') as f:
        f.write("192.168.1.40	test01		#conn\n\
2a01:cb1d:3d5:a100:4a02:2aff:fe07:1efc  ipv6\n")
    X = xythonsrv()
    X.lldebug = True
    X.etcdir = './tests/etc/xython-load/'
    setup_testdir(X, 'load')
    X.init()
    # test remove last /
    assert X.etcdir == './tests/etc/xython-load'
    X.read_configs()
    H = X.find_host("donotexists")
    assert H is None
    H = X.find_host("ipv6")
    assert H is not None
    assert len(X.xy_hosts) == 2
    X.sqc.execute('SELECT * FROM tests')
    results = X.sqc.fetchall()
    assert len(results) == 2

    # we should have 3 hosts with conn on each except for ipv6
    # test that conn is removed from ipv6
    with open("./tests/etc/xython-load/hosts.cfg", 'w') as f:
        f.write("192.168.1.40	test01		#conn\n\
192.168.1.45	test02		#conn\n\
2a01:cb1d:3d5:a100:4a02:2aff:fe07:1efc	ipv6 # noconn\n")
    X.read_configs()
    assert len(X.xy_hosts) == 3
    X.sqc.execute('SELECT * FROM tests')
    results = X.sqc.fetchall()
    assert len(results) == 2
    assert len(X.xy_hosts) == 3

    time.sleep(0.1)
    # we should have 2 hosts with conn on each except for ipv6
    # test that test02 is removed
    with open("./tests/etc/xython-load/hosts.cfg", 'w') as f:
        f.write("192.168.1.40	test01		#conn\n\
2a01:cb1d:3d5:a100:4a02:2aff:fe07:1efc	ipv6 # noconn\n")
    X.read_configs()
    assert len(X.xy_hosts) == 2
    X.sqc.execute('SELECT * FROM tests')
    results = X.sqc.fetchall()
    assert len(results) == 1
    assert len(X.xy_hosts) == 2

    time.sleep(0.1)
    # backup to have a clean git diff
    # TODO find better
    with open("./tests/etc/xython-load/hosts.cfg") as f:
        bh = f.read()
    with open("./tests/etc/xython-load/analysis.cfg") as f:
        ba = f.read()
    time.sleep(1)
    with open("./tests/etc/xython-load/hosts.cfg", "a") as f:
        f.write("0.0.0.0 test0\n")
    with open("./tests/etc/xython-load/analysis.cfg", "a") as f:
        f.write("HOST=test0\n\tPROC test\n")
    X.read_configs()
    # verify new hosts is detected
    H = X.find_host("test0")
    assert H is not None
    time.sleep(0.1)
    with open("./tests/etc/xython-load/analysis.cfg", "a") as f:
        f.write("\tPROC test2\n")
    X.read_configs()
    H = X.find_host("test0")
    assert H is not None
    # verify PROC rules are correctly reseted
    assert len(H.rules["PROC"]) == 2

    with open("./tests/etc/xython-load/hosts.cfg", "w") as f:
        f.write("directory donotexists\n")
    assert not X.read_configs()

    if os.path.exists("./tests/etc/xython-load/hosts.d/new.conf"):
        os.remove("./tests/etc/xython-load/hosts.d/new.conf")

    time.sleep(0.1)
    print("==========================")
    print("DEBUG: initial directory")
    with open("./tests/etc/xython-load/hosts.cfg", "w") as f:
        f.write("directory hosts.d\n")
    ret = X.read_hosts()
    assert ret == X.RET_NEW
    print("==========================")
    print("DEBUG: should nothing happen")
    ret = X.read_hosts()
    assert ret == X.RET_OK
    time.sleep(0.1)
    print("==========================")
    print("add new.conf")
    with open("./tests/etc/xython-load/hosts.d/new.conf", "w") as f:
        f.write("192.168.1.253 itest3\n")
    ret = X.read_hosts()
    assert ret == X.RET_NEW
    assert X.find_host("itest3")

    time.sleep(0.1)
    print("==========================")
    print("remove new.conf")
    os.remove("./tests/etc/xython-load/hosts.d/new.conf")
    ret = X.read_hosts()
    assert ret == X.RET_NEW
    assert not X.find_host("itest3")
    print(X.mtimes_hosts)
    assert "./tests/etc/xython-load/hosts.d/new.conf" not in X.mtimes_hosts

    time.sleep(0.1)
    print("==========================")
    print("Test include non-existant")
    with open("./tests/etc/xython-load/hosts.cfg", "w") as f:
        f.write("include invalid\n")
    ret = X.read_hosts()
    assert ret == X.RET_ERR
    print(X.get_last_error())
    assert X.get_last_error()["msg"].find("No such file or directory")

    print("==========================")
    print("Test include with bad rights")
    with open("./tests/etc/xython-load/hosts.cfg", "w") as f:
        f.write("include hosts-include.cfg\n")
    os.chmod("./tests/etc/xython-load/hosts-include.cfg", 0o000)
    ret = X.read_hosts()
    assert ret == X.RET_ERR
    os.chmod("./tests/etc/xython-load/hosts-include.cfg", 0o640)

    print("==========================")
    print("Test include with good rights")
    os.chmod("./tests/etc/xython-load/hosts-include.cfg", 0o644)
    ret = X.read_hosts()
    assert ret == X.RET_NEW
    assert X.find_host("itest2")
    print(X.mtimes_hosts)
    assert "./tests/etc/xython-load/hosts-include.cfg" in X.mtimes_hosts

    print("==========================")
    print("test getting EDENY on mtime")
    os.chmod("./tests/etc/xython-load/", 0o000)
    ret = X.read_hosts()
    assert ret == X.RET_ERR
    os.chmod("./tests/etc/xython-load/", 0o755)

    print("==========================")
    print("test getting EDENY on mtime")
    os.chmod("./tests/etc/xython-load/", 0o000)
    ret = X.read_hosts()
    assert ret == X.RET_ERR
    os.chmod("./tests/etc/xython-load/", 0o755)

    print("==========================")
    print("no hosts.cfg should fail")
    os.remove('./tests/etc/xython-load/hosts.cfg')
    assert X.read_hosts() == X.RET_ERR

    # restore backup
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

    X.handle_net_message("status+10m test1.coltest red\nfake content\n", "fake")
    X.sqc.execute('SELECT * FROM columns where column == "coltest"')
    results = X.sqc.fetchall()
    assert len(results) == 1

    X.handle_net_message("acknowledge test1.coltest 60m test", "fake")

    # TODO verify content
    X.gen_html("nongreen", None, None, None)
    X.gen_html("all", None, None, None)
    X.gen_html("svcstatus", None, None, None)
    X.gen_html("svcstatus", "test1", "coltest", 0)
    # TODO get the right ts for svcstatus

    # send ack for coltest

    # send bogus ack
    X.handle_net_message("acknowledge invalid.coltest 60m test", "fake")
    X.handle_net_message("acknowledge invalid.invalid 60m test", "fake")
    X.handle_net_message("acknowledge test1.invalid 60m test", "fake")

    # test disable
    X.handle_net_message("disable test1.coltest 60m test", "fake")
    X.handle_net_message("disable invalid.coltest 60m test", "fake")
    X.handle_net_message("disable invalid.invalid 60m test", "fake")
    X.handle_net_message("disable test1.invalid 60m test", "fake")

    # call the scheduler
    X.scheduler()
    # TODO find something that should changed after this call

    # test client data
    f = open("./tests/clientdata/good0")
    data = f.read()
    f.close()

    X.handle_net_message(f"proxy: test\n{data}", "fake")
    X.sqc.execute('SELECT * FROM columns where hostname == "test1"')
    results = X.sqc.fetchall()
    # TODO check each column (disk, cpu, etc..) exists
    expected_cols = ['disk', 'cpu', 'coltest', 'info', 'inode', 'memory', 'ports', 'procs', 'sensor', 'mdstat']
    if has_rrdtool:
        expected_cols.append('xrrd')
    assert len(results) == len(expected_cols)

    # test client data with bogus
    f = open("./tests/clientdata/bogus")
    data = f.read()
    f.close()

    X.handle_net_message(f"proxy: test\n{data}", "fake")

    r = X.handle_net_message('GETSTATUS', '127.0.0.1')
    assert 'ERROR: need more parameters' in r["send"]
    r = X.handle_net_message('GETSTATUS invalid', '127.0.0.1')
    assert 'ERROR: need more parameters' in r["send"]

    r = X.handle_net_message('GETSTATUS invalid invalid', '127.0.0.1')
    assert 'ERROR: no service named' in r["send"]

    r = X.handle_net_message('GETSTATUS test1 coltest', '127.0.0.1')
    print(r)
    assert 'HTML' in r["send"]

    # TODO
    lstat = os.stat(X.xt_logdir + '/logging.log')
    size_orig = lstat.st_size
    X.enable_debug()
    X.debug('test')
    lstat = os.stat(X.xt_logdir + '/logging.log')
    final_size = lstat.st_size
    assert final_size > size_orig

    # CHECK handling of COLUMN_NAME_xxxx
    assert X.colnames["mdstat"] == "mdraid"

    setup_clean(X)


def test_snmpd():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'snmpd')
    X.daemon_name = "xython-snmpd"
    X.init()
    X.read_hosts()
    X.hosts_check_tags()
    # test community
    # do_snmpd(X)
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
    # do_snmpd(X)
    shutil.rmtree(X.xt_data)

def test_snmp_fail():
    r = snmp_get('.1.3.6.1.2.1.1.1.0', '127.0.0.1', 162, 'public')
    print(r)
    assert r['err'] == -1
    assert r['errmsg'] == 'No SNMP response received before timeout'

def test_snmp_get():
    if 'TESTS_SNMP_GET' not in os.environ:
        pytest.skip('Need to set TESTS_SNMP_GET')
        return
    x = os.environ['TESTS_SNMP_GET']
    r = snmp_get('.1.3.6.1.2.1.1.1.0', x, 162, 'public')
    print(r)
    assert r['err'] == -1
    assert r['errmsg'] == 'No SNMP response received before timeout'

    r = snmp_get('.1.3.6.1.2.1.1.1.0', x, 161, 'nopublic')
    print(r)
    assert r['err'] == 0

    r = do_snmpd_disk(x, x, 'nopublic')
    print(r)
    #assert r['err'] == 0
    r = do_snmpd_memory(x, x, 'nopublic')
    print(r)

def test_generic_proto():
    return
    r = do_generic_proto('hostname', '192.168.1.92', 'ftp', 21, ['ftp'], "quit\r\n", '220', ['banner'])
    assert 'txt' in r
    assert 'vsFTPd' in r['txt']
    print(r)

    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldap', 389, ['ldap:invalid'], None, None, ['banner'])
    assert r['color'] == 'red'
    assert 'unknow token' in r['txt']

    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps:invalid'], None, None, ['banner', 'ssl'])
    print(r)
    assert r['color'] == 'red'
    assert 'unknow token' in r['txt']

    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps:timeout=2a'], None, None, ['banner', 'ssl'])
    print(r)
    assert r['color'] == 'red'
    assert 'invalid timeout' in r['txt']

    ts_start = time.time()
    # this should timeout, since no banner will come
    r = do_generic_proto('hostname', '192.168.1.92', 'ldap', 389, ['ldap:timeout=2'], None, None, ['banner'])
    now = time.time()
    assert now - ts_start < 5
    assert r['color'] == 'red'
    assert 'timed out' in r['txt']

    # it should timeout since no banner will come
    ts_start = time.time()
    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps:timeout=2'], None, None, ['banner', 'ssl'])
    now = time.time()
    assert now - ts_start < 5
    assert r['color'] == 'red'

    r = do_generic_proto('hostname', '192.168.1.92', 'ldap', 389, ['ldap'], None, None, None)
    assert r['color'] == 'green'
    r = do_generic_proto('hostname', '192.168.1.92', 'ldap', 389, ['ldap:389'], None, None, None)
    assert r['color'] == 'green'

    r = do_generic_proto('hostname', '192.168.1.92', 'imap', 110, ['imap'], "ABC123 LOGOUT\r\n", '+OK', ['banner'])
    assert r['color'] == 'green'

    # self signed certif
    r = do_generic_proto('hostname', '192.168.1.92', 'imaps', 993, ['imaps'], "quit\r\n", '220', ['banner', 'ssl'])
    assert r['color'] == 'red'
    assert 'CERTIFICATE_VERIFY_FAILED' in r['txt']
    r = do_generic_proto('hostname', '192.168.1.92', 'imaps', 993, ['imaps:verify=0'], "quit\r\n", '220', ['banner', 'ssl'])
    print(r)
    assert r['color'] == 'green'
    return

    # port should be override by url
    r = do_generic_proto('hostname', '192.168.1.92', 'imaps', 993, ['imaps:636'], "quit\r\n", '220', ['banner', 'ssl'])
    print(r)
    assert r['color'] == 'red'
    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps'], None, None, ['ssl'])
    print(r)
    assert r['color'] == 'green'
    r = do_generic_proto('tests2.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps'], None, None, ['ssl'])
    print(r)
    assert r['color'] == 'red'

    # test the binary comp with JNI
    r = do_generic_proto('hostname', '192.168.1.92', 'ajp13', 8009, ['ajp13'], '\x12\x34\x00\x01\x0a', '\x41\x42\x00\x01\x09', None)
    print(r)
    assert r['color'] == 'green'
    r = do_generic_proto('hostname', '192.168.1.92', 'ajp13', 8009, ['ajp13'], '\\x12\\x34\\x00\\x01\\x0a', '\\x41\\x42\\x00\\x01\\x09', None)
    print(r)
    assert r['color'] == 'green'

    r = do_generic_proto('hostname', '192.168.1.92', 'ajp13', 8009, ['ajp13'], '\x12\x34\x00\x01\x0a', '\x41\x42\x00\x01\x08', None)
    print(r)
    assert r['color'] == 'red'
    r = do_generic_proto('hostname', '192.168.1.92', 'ajp13', 8009, ['ajp13'], '\\x12\\x34\\x00\\x01\\x0a', '\\x41\\x42\\x00\\x01\\x08', None)
    print(r)
    assert r['color'] == 'red'

    r = do_generic_proto('hostname', 'hostname.invalid', 'imaps', 993, ['imaps'], "quit\r\n", '220', ['banner', 'ssl'])
    assert r['color'] == 'red'
    assert 'Name or service not known' in r['txt']
    r = do_generic_proto('hostname', 'hostname.invalid', 'imap', 110, ['imaps'], "quit\r\n", '220', ['banner', ])
    assert r['color'] == 'red'
    assert 'Name or service not known' in r['txt']

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
    ret = X.handle_net_message("GETRRD test3\n", "fake")
    assert "send" in ret
    ret = ret["send"]
    assert ret == 'Status: 400 Bad Request\n\nERROR: not enough arguments'
    ret = X.handle_net_message("GETRRD test3 memory\n", "fake")
    assert "send" in ret
    ret = ret["send"]
    assert ret == 'Status: 400 Bad Request\n\nERROR: not enough arguments'

    ret = X.handle_net_message("GETRRD test3 la view\n", "fake")
    assert "bsend" in ret
    ret = ret["bsend"]
    assert len(ret) > 23
    buf = ret[0:23]
    assert 'Content-type: image/png' == buf.decode('UTF8')

    ret = X.handle_net_message("GETRRD test3 sensor view\n", "fake")
    assert "bsend" in ret
    ret = ret["bsend"]
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
    # assert ret.stdout == b'Status: 500 Internal Server Error\n\n\nshowgraph: FAIL to connect to xythond\n'

    envi['QUERY_STRING'] = 'hostname=invalid&service=&sockpath={X.unixsock}'
    ret = subprocess.run(['./xython/showgraph.py'], capture_output=True, env=envi)
    print(ret)
    # assert ret.stdout == b'Status: 500 Internal Server Error\n\n\nshowgraph: FAIL to connect to xythond\n'

    shutil.rmtree(X.xt_data)


def test_celery_ping():
    ret = ping("test", "-invalid", False, False)
    assert ret["color"] == 'red'
    ret = ping("test", "-invalid", True, True)
    assert ret["color"] == 'red'

    test_ping = True
    test_ping6 = True
    # on github ping do not work
    # so do not check result if ping do not work, but still run it to at least catch some possible unhandled exceptions
    if 'GITHUB_ACTION' in os.environ:
        print("INFO: on github testing ping is disabled")
        test_ping = False
    if 'HAS_IPV6' in os.environ:
        if os.environ['HAS_IPV6'] == 'False':
            print("INFO: IPV6 ping is disabled")
            test_ping6 = False
    # TODO test ping binary is availlable
    ret = ping("test", DEFAULT_PING_TARGET, False, False)
    print(ret)
    if test_ping:
        assert ret["color"] == 'green'
    ret = ping("test", DEFAULT_PING_TARGET, True, False)
    if test_ping:
        assert ret["color"] == 'green'
    ret = ping("test", "dual.xython.fr", True, True)
    if test_ping and test_ping6:
        # ipv6 could be unvaillable
        print(ret)
        if re.search('Cannot assign requested address', ret['txt']):
            pytest.skip('IPV6 seems not availlable')
        else:
            print(os.environ)
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
    print(ret)
    assert ret["color"] == 'red'
    err = re.search("Connection refused", ret['txt'])
    assert err

    #ret = do_generic_proto("test", "tests.xython.fr", 'ldaps:444', None, ['ldaps:hostname=tests.xython.fr'], None, None, "ssl")
    #print(ret)
    #assert ret["color"] == 'red'
    #err = re.search("Connection refused", ret['txt'])
    #assert err

    print("DEBUG: tests: send GET / and expect to find HTTP")
    # ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldaps:hostname=tests.xython.fr'], "GET /\\r\\nHTTP/1.1\\r\\nHost: test.xython.fr\\x13\\x10\\r\\n", "\\x48\\x54\\x54\\x50", "banner, ssl")
    ret = do_generic_proto("test", "tests.xython.fr", 'ldap', 443, ['ldaps:hostname=tests.xython.fr'], "\\x47\\x45\\x54\\x20\\x2F\\x47HTTP/1.1\\x13\\x10Host: test.xython.fr\\x13\\x10\\r\\n", "\\x48\\x54\\x54\\x50", "banner, ssl")
    assert ret["color"] == 'green'

def test_celery_protocols_timeout():
    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldap', 389, ['ldap:timeout='], None, None, ['banner'])
    assert r['color'] == 'red'
    assert 'invalid timeout' in r['txt']
    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldap', 389, ['ldap:timeout=x'], None, None, ['banner'])
    assert r['color'] == 'red'
    assert 'invalid timeout' in r['txt']

    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps:timeout='], None, None, ['banner', 'ssl'])
    assert r['color'] == 'red'
    assert 'invalid timeout' in r['txt']
    r = do_generic_proto('tests.xython.fr', 'tests.xython.fr', 'ldaps', 443, ['ldaps:timeout=x'], None, None, ['banner', 'ssl'])
    print(r)
    assert r['color'] == 'red'
    assert 'invalid timeout' in r['txt']


def test_celery_tssh():
    r = xssh(None, None)
    assert r.dret['color'] == 'red'
    r = xssh('hostname', None)
    assert r.dret['color'] == 'red'
    r = xssh(None, 'invalid')
    assert r.dret['color'] == 'red'

    # no tssh://
    r = xssh('valid', 'invalid')
    assert r.dret['color'] == 'red'

    # miss ;
    r = xssh('valid', 'tssh://')
    assert r.dret['color'] == 'red'

    # no @
    r = xssh('valid', 'tssh://hostname;')
    assert r.dret['color'] == 'red'

    # empty host
    r = xssh('valid', 'tssh://root@;')
    assert r.dret['color'] == 'red'

    # empty user
    r = xssh('valid', 'tssh://@hostname;')
    assert r.dret['color'] == 'red'

    # empty test
    r = xssh('valid', 'tssh://root@hostname;')
    assert r.dret['color'] == 'red'

    # test is invalid
    r = xssh('valid', 'tssh://root@hostname;invalid')
    assert r.dret['color'] == 'red'

    # test invalid user:pass
    r = xssh('valid', 'tssh://root:@test;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == 'ERROR: password is empty'

    # test invalid user:pass
    r = xssh('valid', 'tssh://:password@test;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == 'ERROR: username is empty'

    # test invalid port
    r = xssh('valid', 'tssh://root@test:invalid:extraarg;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == 'ERROR: invalid hostname:port'

    # test invalid port
    r = xssh('valid', 'tssh://root@test:invalid;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == 'ERROR: port invalid is not a number'

    # test invalid port
    r = xssh('valid', 'tssh://root@test:70000;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == 'ERROR: port 70000 is out of range'

    r = xssh('valid', 'tssh://root@test:7000;rsakey=x=;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Wrong key token rsakey=x=\n"
    r = xssh('valid', 'tssh://root@test:7000;edkey=x=;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Wrong key token edkey=x=\n"


    r = xssh('valid', 'tssh://root@test:7000;edkey=;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load : [Errno 2] No such file or directory: ''\n"
    r = xssh('valid', 'tssh://root@test:7000;rsakey=;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load : [Errno 2] No such file or directory: ''\n"

    # test non existant rsakey
    r = xssh('valid', 'tssh://root@test:7000;rsakey=notexists;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load notexists: [Errno 2] No such file or directory: 'notexists'\n"
    r = xssh('valid', 'tssh://root@test:7000;edkey=notexists;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load notexists: [Errno 2] No such file or directory: 'notexists'\n"

    # test invalid rsakey
    r = xssh('valid', 'tssh://root@test:7000;rsakey=./tests/ssh/invalid;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load ./tests/ssh/invalid: not a valid RSA private key file\n"

    # test invalid edkey
    r = xssh('valid', 'tssh://root@test:7000;edkey=./tests/ssh/invalid;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load ./tests/ssh/invalid: not a valid OPENSSH private key file\n"

    # test permission denied
    os.chmod('tests/ssh/eperm', 0o000)
    r = xssh('valid', 'tssh://root@test:7000;edkey=./tests/ssh/eperm;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load ./tests/ssh/eperm: [Errno 13] Permission denied: './tests/ssh/eperm'\n"
    r = xssh('valid', 'tssh://root@test:7000;rsakey=./tests/ssh/eperm;client')
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to load ./tests/ssh/eperm: [Errno 13] Permission denied: './tests/ssh/eperm'\n"
    os.chmod('tests/ssh/eperm', 0o640)

    r = xssh('valid', 'tssh://root@test:22;ping:')
    assert r.dret['color'] == 'red'
    r = xssh('valid', f'tssh://root@test:22;ping:{DEFAULT_PING_TARGET}:')
    assert r.dret['color'] == 'red'

    # test invalid timeout
    r = xssh('valid', f'tssh://root@test;timeout=;ping:{DEFAULT_PING_TARGET}:')
    assert r.dret['color'] == 'red'
    r = xssh('valid', f'tssh://root@test;timeout=4=;ping:{DEFAULT_PING_TARGET}:')
    assert r.dret['color'] == 'red'
    r = xssh('valid', f'tssh://root@test;timeout=invalid;ping:{DEFAULT_PING_TARGET}:')
    assert r.dret['color'] == 'red'
    r = xssh('valid', f'tssh://root@test;timeout=-4;ping:{DEFAULT_PING_TARGET}:')
    assert r.dret['color'] == 'red'

    # valid tests cases
    r = xssh('valid', 'tssh://root@test;client')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0

    r = xssh('valid', 'tssh://root@test:22;client')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0

    r = xssh('valid', 'tssh://root@test:22;edkey=./tests/ssh/ed25519/valid;client')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0
    r = xssh('valid', 'tssh://root@test:22;rsakey=./tests/ssh/rsa/valid;client')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0

    r = xssh('valid', 'tssh://root@test;timeout=600;client')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0

    r = xssh('valid', f'tssh://root@test:22;ping:{DEFAULT_PING_TARGET}')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0

    r = xssh('valid', f'tssh://root@test:7777;ping:{DEFAULT_PING_TARGET}')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0
    assert r.port == 7777


    # this live tests could be performed anywhere
    r = xssh('valid', f'tssh://root@test.invalid;ping:{DEFAULT_PING_TARGET}')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0
    r.run()
    assert r.dret['color'] == 'red'
    assert r.dret['txt'] == "status+10m valid.tssh red\n&red Failed to connect on test.invalid: [Errno -2] Name or service not known\n"

    r = xssh('valid', f'tssh://root@169.254.254.254;timeout=1;ping:{DEFAULT_PING_TARGET}')
    assert r.dret['color'] == 'green'
    assert len(r.actions) > 0
    r.run()
    assert r.dret['color'] == 'red'

def test_celery_tssh_macs_mismatch():
    # tested with sshd-openssh-macs-only docker
    if 'TESTS_XSSH_OPENSSH_MACS_ONLY' in os.environ:
        x = os.environ['TESTS_XSSH_OPENSSH_MACS_ONLY']
        r = xssh('valid', f'tssh://{x};rsakey=./tests/ssh/rsa/valid;ping:{DEFAULT_PING_TARGET}')
        print(r.dret)
        assert r.dret['color'] == 'green'
        assert len(r.actions) > 0
        r.run()
        assert r.dret['color'] == 'red'
    else:
        pytest.skip('Need to set TESTS_XSSH_OPENSSH_MACS_ONLY')

def test_celery_tssh_crefused():
    # tested with sshd-openssh-mac-only docker
    if 'TESTS_XSSH_CONNECTION_REFUSED' in os.environ:
        x = os.environ['TESTS_XSSH_CONNECTION_REFUSED']
        r = xssh('valid', f'tssh://{x};ping:{DEFAULT_PING_TARGET}')
        assert r.dret['color'] == 'green'
        assert len(r.actions) > 0
        r.run()
        assert r.dret['color'] == 'red'
    else:
        pytest.skip('Need to set TESTS_XSSH_CONNECTION_REFUSED')

def test_celery_tssh_ping_notfound():
    # tested with sshd-debian-noping docker
    if 'TESTS_XSSH_SUCCESS_NOPING' in os.environ:
        x = os.environ['TESTS_XSSH_SUCCESS_NOPING']
        r = xssh('valid', f'tssh://{x};rsakey=./tests/ssh/rsa/valid;ping:{DEFAULT_PING_TARGET}')
        assert r.dret['color'] == 'green'
        assert len(r.actions) > 0
        r.run()
        assert r.dret['color'] == 'red'
        assert re.search('sh: 1: ping: not found', r.dret['txt'])
    else:
        pytest.skip('Need to set TESTS_XSSH_SUCCESS_NOPING')

def test_celery_tssh_ping_success():
    # tested with sshd-debian-ping docker
    if 'TESTS_XSSH_SUCCESS_PING' in os.environ:
        x = os.environ['TESTS_XSSH_SUCCESS_PING']
        r = xssh('valid', f'tssh://{x};rsakey=./tests/ssh/rsa/valid;ping:{DEFAULT_PING_TARGET}')
        assert r.dret['color'] == 'green'
        assert len(r.actions) > 0
        r.run()
        assert r.dret['color'] == 'green'
        assert re.search('4 packets transmitted, 4 received', r.dret['txt'])
    else:
        pytest.skip('Need to set TESTS_XSSH_SUCCESS_PING')

def test_celery_tssh_client_success():
    # sshd-debian
    if 'TESTS_XSSH_SUCCESS_CLIENT' in os.environ:
        x = os.environ['TESTS_XSSH_SUCCESS_CLIENT']
        r = xssh('valid', f'tssh://{x};rsakey=./tests/ssh/rsa/valid;client')
        assert r.dret['color'] == 'green'
        assert len(r.actions) > 0
        r.run()
        assert r.dret['color'] == 'green'
        assert 'data' in r.dret
        assert re.search('client debian.linux linux', r.dret['data'])
    else:
        pytest.skip('Need to set TESTS_XSSH_SUCCESS_CLIENT')


def test_net():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'net')
    assert not X.set_netport(0)
    assert not X.set_netport(100000)
    assert X.set_netport(1000)
    assert X.netport == 1000

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

# permit to check if timings are okay
def todo_timing():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'misc')
    X.init()
    X.wwwdir = X.xt_data

    i = 0
    while i < 1000:
        i += 1
        hostname = f'test{i}'
        H = xy_host(f'test{i}')
        X.add_host(H)
        X.gen_column_info(hostname)
        c = 0
        data = "\n\n\n\n"
        now = int(time.time())
        while c < 30:
            colors = ['red', 'yellow', 'green', 'blue', 'green', 'green', 'green']
            color = colors[random.randint(0, len(colors) -1)]
            cname = f"col{c}"
            X.sqc.execute('INSERT OR REPLACE INTO columns(hostname, column, ts, expire, color, ackend, ackcause) VALUES (?, ?, ?, ?, ?, ?, ?)', (hostname, cname, now, 3600, color, None, None))
            c += 1
    print(len(X.xy_hosts))
    ts = time.time()
    H = X.find_host('test500')
    print(time.time() - ts)
    ts = time.time()
    ret = X.gen_html('nongreen', None, None, None)
    print(f"NONGREEN GENTIME {time.time() - ts}")
    print(X.stats)

    shutil.rmtree(X.xt_data)

def test_pages():
    X = xythonsrv()
    X.etcdir = './tests/etc/xython-page/'
    setup_testdir(X, 'page')
    X.lldebug = True
    X.init()

    X.sqc.execute('SELECT * FROM columns')
    results = X.sqc.fetchall()
    print(results)
    X.sqc.execute('SELECT * FROM pages')
    results = X.sqc.fetchall()
    for page in results:
        print(page)
    print(X.pagelist)

    X.gen_htmls()

    f = open(f"{X.wwwdir}/xython.html")
    html = f.read()
    f.close()

    assert "default01" in html
    assert "italy01" in html
    assert "donotexists" not in html

    f = open(f"{X.wwwdir}/france.html")
    html = f.read()
    f.close()

    assert "france01" in html
    assert "paris01" not in html

    f = open(f"{X.wwwdir}/france/paris.html")
    html = f.read()
    f.close()

    assert "france01" not in html
    assert "paris01" in html

    f = open(f"{X.wwwdir}/england.html")
    html = f.read()
    f.close()

    assert "default01" not in html
    assert "england01" in html
    assert "www01" in html
    assert "www02" in html
    assert "databases" in html
    assert "db01" in html
    assert "db02" in html

    f = open(f"{X.wwwdir}/test.html")
    html = f.read()
    f.close()

    assert "A group title with spaces" in html

    X.html_page("acknowledgements")
    X.html_page("expires")
    X.html_page("topchanges")

    X.gen_top_changes(xyevent(time.time() - 180), xyevent(time.time()))
    # error cases
    X.gen_top_changes(xyevent(time.time() - 60), "")
    X.gen_top_changes("", xyevent(time.time() - 60))

    print("DEBUG: Add color changes")
    err = X.column_update('england01', 'coltest', 'green', time.time(), 'test', 120, "xython-tests")
    assert err == 1
    err = X.column_update('england01', 'coltest', 'red', time.time(), 'test', 120, "xython-tests")
    assert err == 1
    time.sleep(1)
    X.gen_top_changes(xyevent(time.time() - 180), xyevent(time.time()))

    setup_clean(X)

def test_purple():
    X = xythonsrv()
    X.etcdir = './tests/etc/full/'
    setup_testdir(X, 'purple')
    X.lldebug = True
    X.init()

    # check error condition with empty colname
    err = X.column_update('testpurple', '', 'green', 0, 'test', 120, "xython-tests")
    assert err == 2

    err = X.column_update('testpurple', 'coltest', 'green', 0, 'test', 120, "xython-tests")
    assert err == 1

    X.check_purples()
    assert X.get_column_color('testpurple', 'coltest') == 'green'

    assert X.parse_disable('disable testpurple.coltest 30d whynot')
    assert X.get_column_color('testpurple', 'coltest') == 'blue'

    # TODO test enable
    #err = X.parse_enable('enable testpurple.coltest')

    # timing test
    err = X.column_update('testpurple', 'coltest2', 'green', 0, 'test', 1, "xython-tests")
    assert err == 1
    time.sleep(2)
    X.check_purples()

    assert X.get_column_color('testpurple', 'coltest2') == 'purple'


    # final test with multiple column which shout not be touched
    err = X.column_update('testpurple', 'colgreen', 'green', 0, 'test', 120, "xython-tests")
    assert err == 1
    err = X.column_update('testpurple', 'colyellow', 'yellow', 0, 'test', 120, "xython-tests")
    assert err == 1
    err = X.column_update('testpurple', 'colred', 'red', 0, 'test', 120, "xython-tests")
    assert err == 1
    err = X.column_update('testpurple', 'colbad', 'red', 0, 'test', 0, "xython-tests")
    assert err == 1
    time.sleep(1)

    X.check_purples()
    assert X.get_column_color('testpurple', 'colbad') == 'purple'
    assert X.get_column_color('testpurple', 'colgreen') == 'green'
    assert X.get_column_color('testpurple', 'colyellow') == 'yellow'
    assert X.get_column_color('testpurple', 'colred') == 'red'

    assert X.parse_disable('disable testpurple.colbad 30d whynot')
    assert X.get_column_color('testpurple', 'colbad') == 'blue'
    assert X.get_column_color('testpurple', 'colgreen') == 'green'
    assert X.get_column_color('testpurple', 'colyellow') == 'yellow'
    assert X.get_column_color('testpurple', 'colred') == 'red'

    setup_clean(X)

def test_dmesg():
    X = xythonsrv()
    # test a directory without dmesg.regex
    X.etcdir = './tests/etc/xython-sensors/'
    setup_testdir(X, 'dmesg')
    X.lldebug = True
    X.init()

    f = open("./tests/dmesg/dmesg-rpi")
    dmesgrpi = f.read()
    f.close()
    X.parse_dmesg("test01", dmesgrpi, "fake")

    f = open("./tests/dmesg/dmesg-red")
    dmesgred = f.read()
    f.close()
    X.parse_dmesg("test01", dmesgred, "fake")

    setup_clean(X)

def test_mdstat():
    X = xythonsrv()
    X.etcdir = './tests/etc/xython-sensors/'
    setup_testdir(X, 'mdstat')
    X.lldebug = True
    X.init()

    f = open("./tests/mdstat/mdstat1")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat1")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat2")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat3")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat4")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat5")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat6")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat-rebuild1")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat-rebuild2")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat-rebuild3")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat-rebuild4")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    f = open("./tests/mdstat/mdstat-corrupt")
    md1 = f.read()
    f.close()
    X.parse_mdstat("test01", md1, "fake")

    setup_clean(X)
