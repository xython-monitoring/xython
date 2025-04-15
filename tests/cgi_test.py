#!/usr/bin/env python3

import fcntl
import os
import socket
import subprocess
import sys
import time


def run_cgi(cgibin, UNIXSOCK, envi, close_after_accept, maxclient=1):
    ret = {}
    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)
    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    us.bind(UNIXSOCK)
    us.listen(10)
    us.setblocking(0)

    sin = open("tests/cgi/proxy.in")
    pp = subprocess.Popen(cgibin, stdout=subprocess.PIPE, env=envi, stdin=sin)
    flags = fcntl.fcntl(pp.stdout, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(pp.stdout, fcntl.F_SETFL, flags)
    timeout = 0
    theend = False
    numclient = 0
    MAXTIMEOUT = 15
    while timeout < MAXTIMEOUT and not theend:
        try:
            c, adidr = us.accept()
            numclient += 1
            if numclient == 2:
                # ugly hack
                close_after_accept = False
            if close_after_accept:
                c.close()
            else:
                r = c.recv(64000)
                ret["recv"] = r
                c.send(b"SENDSTRING")
                c.close()
            if numclient >= maxclient:
                theend = True
        except BlockingIOError:
            print(f"TIMEOUT {timeout}")
            timeout += 1
        time.sleep(0.3)
        pp.poll()
    if timeout >= MAXTIMEOUT:
        ret["error"] = "timeout"
    pp.stdout.flush()
    us.close()
    if os.path.exists(UNIXSOCK):
        os.remove(UNIXSOCK)
    outs, err = pp.communicate()
    print(f"OUT={outs}")
    ret["out"] = outs
    print(pp)
    return ret


def test_proxy():
    cgibin = [sys.executable, "-m", "coverage", 'run', './cgi/proxy.py']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: no REQUEST_METHOD\n'
    assert ret.stderr == b''

    envi = {}
    envi["REQUEST_METHOD"] = 'invalid'
    #ret = subprocess.run(cgibin, capture_output=True, env=envi)
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: REQUEST_METHOD is not POST\n'
    assert ret.stderr == b''

    envi = {}
    envi["REQUEST_METHOD"] = 'POST'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: no CONTENT_TYPE\n'
    assert ret.stderr == b''

    envi["CONTENT_TYPE"] = 'invalid'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: CONTENT_TYPE is not multipart/form-data\n'
    assert ret.stderr == b''

    envi["CONTENT_TYPE"] = 'multipart/form-data'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: no boundary in CONTENT_TYPE\n'
    assert ret.stderr == b''

    sin = open("tests/cgi/proxy-noheader.in")
    envi["CONTENT_TYPE"] = 'multipart/form-data; boundary=AAA'
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    sin.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: wrong format\n'
    assert ret.stderr == b''

    sin = open("tests/cgi/empty.in")
    envi["CONTENT_TYPE"] = 'multipart/form-data; boundary=AAA'
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    sin.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: no boundary in content\n'
    assert ret.stderr == b''

    sin = open("tests/cgi/proxy-noend.in")
    envi["CONTENT_TYPE"] = 'multipart/form-data; boundary=AAA'
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    sin.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: no end\n'
    assert ret.stderr == b''

    sin = open("tests/cgi/proxy.in")
    envi["CONTENT_TYPE"] = 'multipart/form-data; boundary=AAA'
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    print(ret)
    sin.close()
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nERROR: no REMOTE_ADDR\n'
    assert ret.stderr == b''

    UNIXSOCK = "tests/cgi/xython-proxy.sock"
    envi["XYTHON_SOCK"] = UNIXSOCK

    print("================================= FileNotFoundError:")
    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)
    envi["REMOTE_ADDR"] = '127.0.0.1'
    sin = open("tests/cgi/proxy.in")
    envi["CONTENT_TYPE"] = 'multipart/form-data; boundary=AAA'
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    print(ret)
    sin.close()
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nFAIL to connect to xythond, no such file or directory\n'
    assert ret.stderr == b''

    # ConnectionRefusedError:
    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    us.bind(UNIXSOCK)
    sin = open("tests/cgi/proxy.in")
    envi["CONTENT_TYPE"] = 'multipart/form-data; boundary=AAA'
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    print(ret)
    sin.close()
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/plain\n\nFAIL to connect to xythond\n'
    assert ret.stderr == b''

    print("=================================")
    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)
    us.listen(10)
    us.setblocking(0)

    sin = open("tests/cgi/proxy.in")
    pp = subprocess.Popen('./cgi/proxy.py', stdout=subprocess.PIPE, env=envi, stdin=sin)
    flags = fcntl.fcntl(pp.stdout, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(pp.stdout, fcntl.F_SETFL, flags)
    timeout = 0
    theend = False
    while timeout < 10 and not theend:
        try:
            c, addr = us.accept()
            print("ACCEPT")
            c.close()
            theend = True
        except BlockingIOError:
            print("WAIT")
            timeout += 1
        time.sleep(1)
        ret = pp.poll()
    pp.stdout.flush()
    us.close()
    outs, err = pp.communicate()
    print(f"OUT={outs}")
    print(f"ERR={err}")

    ret = run_cgi(cgibin, UNIXSOCK, envi, True)
    print(f"RET={ret}")
    assert "recv" not in ret

    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert ret["recv"] == b'HTTPTLSproxy 127.0.0.1\nCLIENTDATAS'
    assert ret["out"] == b'Content-type: text/plain\n\nSENDSTRING\n'

    us.close()
    if os.path.exists(UNIXSOCK):
        os.remove(UNIXSOCK)


def test_topchanges():
    cgibin = [sys.executable, "-m", "coverage", 'run', './cgi/topchanges.py']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: no REQUEST_METHOD\n'
    assert ret.stderr == b''

    envi = {}
    envi["REQUEST_METHOD"] = 'invalid'
    #ret = subprocess.run(cgibin, capture_output=True, env=envi)
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: REQUEST_METHOD is not GET\n'
    assert ret.stderr == b''

    envi = {}
    envi["REQUEST_METHOD"] = 'GET'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 1
    assert ret.stdout == b'Content-type: text/html\n\nERROR: not runned as CGI\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'invalid'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: no starttime\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=invalid'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: invalid FROMTIME date\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=invalid&TOTIME'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: invalid FROMTIME date\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=invalid&TOTIME='
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: invalid FROMTIME date\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=&TOTIME=invalid'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: invalid TOTIME date\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=2023%2F01%2F01%4011%3A11%3A11'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: no TOTIME\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=2023%2F01%2F01%4011%3A11%3A11&TOTIME=invalid'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nERROR: invalid TOTIME date\n'
    assert ret.stderr == b''

    UNIXSOCK = "tests/cgi/xython-topchanges.sock"
    envi["XYTHON_SOCK"] = UNIXSOCK

    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)
    envi["QUERY_STRING"] = 'FROMTIME=2023%2F01%2F01%4011%3A11%3A11&TOTIME='
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nFAIL to connect to xythond, [Errno 2] No such file or directory\n'
    assert ret.stderr == b''

    envi["QUERY_STRING"] = 'FROMTIME=2023%2F01%2F01%4011%3A11%3A11&TOTIME=2023%2F01%2F01%4011%3A11%3A11'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nFAIL to connect to xythond, [Errno 2] No such file or directory\n'
    assert ret.stderr == b''

    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    us.bind(UNIXSOCK)

    envi["QUERY_STRING"] = 'FROMTIME=2023%2F01%2F01%4011%3A11%3A11&TOTIME=2023%2F01%2F01%4011%3A11%3A11'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nFAIL to connect to xythond, [Errno 111] Connection refused\n'
    assert ret.stderr == b''

    us.close()
    if os.path.exists(UNIXSOCK):
        os.remove(UNIXSOCK)

    ret = run_cgi(cgibin, UNIXSOCK, envi, True)
    print(f"RET={ret}")
    assert "recv" not in ret

    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert ret["recv"] == b'TOPCHANGES 2023/01/01@11:11:11 2023/01/01@11:11:11\n'
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    us.close()
    if os.path.exists(UNIXSOCK):
        os.remove(UNIXSOCK)

def test_getpages():
    cgibin = [sys.executable, "-m", "coverage", 'run', './cgi/getpage.py']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 1
    assert ret.stdout == b'Content-type: text/html\n\nERROR: not runned as CGI\n'
    assert ret.stderr == b''

    envi = {}
    UNIXSOCK = "tests/cgi/xython.sock"
    envi["XYTHON_SOCK"] = UNIXSOCK

    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)

    ret = run_cgi(cgibin, UNIXSOCK, envi, True)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: not runned as CGI\n'

    envi["QUERY_STRING"] = 'page=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

def test_xythoncgi():
    cgibin = [sys.executable, "-m", "coverage", 'run', './cgi/xythoncgi.py']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 1
    assert ret.stdout == b'Content-type: text/html\n\nERROR: not runned as CGI\n'
    assert ret.stderr == b''

    envi = {}
    UNIXSOCK = "tests/cgi/xython-xythoncgi.sock"
    envi["XYTHON_SOCK"] = UNIXSOCK

    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)

    envi["QUERY_STRING"] = 'hostname=toto&service=test'
    ret = subprocess.run(cgibin, capture_output=True, env=envi)
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\nFAIL to connect to xythond, [Errno 2] No such file or directory\n'
    assert ret.stderr == b''

    del(envi["QUERY_STRING"])
    ret = run_cgi(cgibin, UNIXSOCK, envi, True)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: not runned as CGI\n'

    envi["QUERY_STRING"] = 'service=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: no hostname\n'

    envi["QUERY_STRING"] = 'hostname=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: no service\n'

    envi["QUERY_STRING"] = 'HOST=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: no service\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    envi["QUERY_STRING"] = 'HOST=toto&SERVICE=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&timebuf=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=invalid'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: invalid action\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=ack'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: ack need cause\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=ack&cause=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: ack need duration\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=ack&cause=test&duration=10y'
    ret = run_cgi(cgibin, UNIXSOCK, envi, True, maxclient=2)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=disable'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: disable need cause\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=disable&cause=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: disable need duration\n'

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=disable&cause=test&duration=10y'
    ret = run_cgi(cgibin, UNIXSOCK, envi, True, maxclient=2)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: disable need dsvc\n'

    envi["QUERY_STRING"] = 'hostname=toto&service=test&action=disable&cause=test&duration=10y&dservice=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, True, maxclient=2)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    envi["QUERY_STRING"] = 'HOST=toto&SERVICE=test&action=disable&cause=test&duration=10y&DSERVICE=toto'
    ret = run_cgi(cgibin, UNIXSOCK, envi, True, maxclient=2)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    envi["QUERY_STRING"] = 'HOST=toto&SERVICE=test&TIMEBUF=tutu'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert "timeout" not in ret
    assert ret["recv"] == b'GETSTATUS toto test tutu\n'
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

    us = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    us.bind(UNIXSOCK)

    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert ret["recv"] == b'GETSTATUS toto test\n'
    assert ret["out"] == b'Content-type: text/html\n\nSENDSTRING\n'

