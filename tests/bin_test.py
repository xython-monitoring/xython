#!/usr/bin/env python3

import shutil
import subprocess
import sys

def _xythonc_bin():
    """Locate the installed xythonc console script."""
    found = shutil.which("xythonc")
    if found:
        return found
    cand = os.path.join(os.path.dirname(sys.executable), "xythonc")
    if os.path.exists(cand):
        return cand
    return None

def _xythond_bin():
    """Locate the installed xythond."""
    found = shutil.which("xythond")
    if found:
        return found
    cand = os.path.join(os.path.dirname(sys.executable), "xythond")
    if os.path.exists(cand):
        return cand
    return None

def test_bin():
    xythonc = _xythonc_bin()
    xythond = _xythond_bin()

    xbin = [sys.executable, "-m", "coverage", 'run', xythond, '-h']
    ret = subprocess.run(xbin, capture_output=True, env=None)
    print(ret)
    assert ret.returncode == 0
    assert b'usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', xythonc, '-h']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    print(ret)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', xythonc, '127.0.0.1:66']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', xythonc, '--debug', '127.0.0.1']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', xythonc, '--debug', '127.0.0.1:66']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'Usage:' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', xythonc, '--debug', '127.0.0.1:66', 'test']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'ERROR: fail to connect on 127.0.0.1:66 [Errno 111] Connection refused' in ret.stdout
    assert ret.stderr == b''

    cgibin = [sys.executable, "-m", "coverage", 'run', xythonc,
              '--debug', 'invalid.invalid:66', 'test']
    ret = subprocess.run(cgibin, capture_output=True, env=None)
    assert ret.returncode == 0
    assert b'ERROR: fail to connect on invalid.invalid:66 [Errno -2] Name or service not known' in ret.stdout
    assert ret.stderr == b''
