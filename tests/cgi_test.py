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


def test_showgraph():
    cgibin = [sys.executable, "-m", "coverage", 'run', './cgi/showgraph.py']

    # showgraph reads stdin unconditionally, so early-exit error cases must be
    # fed a stdin to avoid inheriting/blocking on pytest's stdin.
    empty = open("tests/cgi/empty.in")
    ret = subprocess.run(cgibin, capture_output=True, env={}, stdin=empty)
    empty.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Status: 400 Bad Request\n\n\n\nno hostname\n\n'
    assert ret.stderr == b''

    envi = {}
    envi["QUERY_STRING"] = 'hostname=toto'
    empty = open("tests/cgi/empty.in")
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=empty)
    empty.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Status: 400 Bad Request\n\n\n\nno service\n\n'
    assert ret.stderr == b''

    # hostname supplied via the POST body (stdin) instead of QUERY_STRING; a
    # missing service still errors, proving the stdin parsing path works.
    del(envi["QUERY_STRING"])
    sin = open("tests/cgi/showgraph-post.in")
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=sin)
    sin.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Status: 400 Bad Request\n\n\n\nno service\n\n'
    assert ret.stderr == b''

    # action=menu is answered without touching the daemon socket.
    envi["QUERY_STRING"] = 'hostname=toto&service=test&action=menu'
    empty = open("tests/cgi/empty.in")
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=empty)
    empty.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Content-type: text/html\n\n<html>\n'
    assert ret.stderr == b''

    UNIXSOCK = "tests/cgi/xython-showgraph.sock"
    envi["XYTHON_SOCK"] = UNIXSOCK

    # no listener on the socket -> connection failure
    if os.path.exists(UNIXSOCK):
        os.unlink(UNIXSOCK)
    envi["QUERY_STRING"] = 'hostname=toto&service=test'
    empty = open("tests/cgi/empty.in")
    ret = subprocess.run(cgibin, capture_output=True, env=envi, stdin=empty)
    empty.close()
    print(ret)
    assert ret.returncode == 0
    assert ret.stdout == b'Status: 500 Internal Server Error\n\n\nshowgraph: FAIL to connect to xythond\n'
    assert ret.stderr == b''

    # successful GETRRD: the daemon receives the request and its raw reply is
    # streamed back verbatim (no Content-type header is added by showgraph).
    envi["QUERY_STRING"] = 'HOST=toto&SERVICE=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert ret["recv"] == b'GETRRD toto test view'
    assert ret["out"] == b'SENDSTRING'

    # action overrides the default 'view' in the GETRRD request
    envi["QUERY_STRING"] = 'HOST=toto&SERVICE=test&action=cpu'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert ret["recv"] == b'GETRRD toto test cpu'
    assert ret["out"] == b'SENDSTRING'

    # lower-case host/service aliases and the debug flag all reach the daemon
    envi["QUERY_STRING"] = 'host=toto&service=test&debug=1'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert ret["recv"] == b'GETRRD toto test view'
    assert ret["out"] == b'SENDSTRING'

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

    # state-changing actions must use POST (CSRF): a GET ack is refused
    envi["QUERY_STRING"] = 'hostname=toto&SERVICE=test&action=ack&cause=test&duration=10y'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert "recv" not in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: action requires POST\n'

    # from here on the ack/disable form is submitted as POST
    envi["REQUEST_METHOD"] = "POST"

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

    # blueing '*' (disable every column of the host) is a legitimate target
    # and must reach the daemon, see xython.disable. The cgi hardening must not
    # reject the '*' wildcard as an invalid dservice.
    envi["QUERY_STRING"] = 'hostname=toto&service=test&action=disable&cause=test&duration=10y&dservice=*'
    ret = run_cgi(cgibin, UNIXSOCK, envi, True, maxclient=2)
    print(f"RET={ret}")
    assert "out" in ret
    # reaching GETSTATUS proves the '*' dservice passed validation instead of
    # being rejected with 'ERROR: invalid dservice'
    assert ret["recv"] == b'GETSTATUS toto test\n'
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

    # path traversal: a hostname trying to escape the histlogs tree must be
    # rejected by the CGI before any data is sent to the daemon
    envi["QUERY_STRING"] = 'HOST=../../etc&SERVICE=test'
    ret = run_cgi(cgibin, UNIXSOCK, envi, False)
    print(f"RET={ret}")
    assert "out" in ret
    assert "recv" not in ret
    assert ret["out"] == b'Content-type: text/html\n\nERROR: invalid hostname\n'

