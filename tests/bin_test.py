#!/usr/bin/env python3

import subprocess
import sys


def test_bin():
    cgibin = [sys.executable, "-m", "coverage", 'run', './xython/xython_client.py', '-h']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    print(ret)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', './xython/xython_client.py', '127.0.0.1:66']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', './xython/xython_client.py', '--debug', '127.0.0.1']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', './xython/xython_client.py', '--debug', '127.0.0.1:66']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', './xython/xython_client.py', '--debug', '127.0.0.1:66', 'test']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'ERROR: fail to connect on 127.0.0.1:66 [Errno 111] Connection refused' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', './xython/xython_client.py',
              '--debug', 'invalid.invalid:66', 'test']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'ERROR: fail to connect on invalid.invalid:66 [Errno -2] Name or service not known' in ret.stdout
    assert ret.stderr == b''
