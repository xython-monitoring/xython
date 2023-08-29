#!/usr/bin/env python3

"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

from celery import Celery
import subprocess
import os
import time
import re
import requests
import socket
from importlib.metadata import version
from xython.common import xytime

# TODO permit to configure localhost
app = Celery('tasks', backend='redis://localhost', broker='redis://localhost')


@app.task
def ping(hostname, t):
    env = os.environ
    env["LANG"] = 'C'
    env["LC_ALL"] = 'C'
    color = 'green'
    ret = subprocess.run(["ping", "-c", "1", t], capture_output=True)
    if ret.returncode != 0:
        color = 'red'
    hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
    dret = {}
    dret["color"] = color
    dret["txt"] = hdata
    dret["hostname"] = hostname
    dret["type"] = 'conn'
    return dret


@app.task
def dohttp(hostname, urls):
    verify = True
    hdata = ""
    httpstate = ""
    httpcount = 0
    options = ""
    need_httpcode = 200
    headers = {}
    headers["User-Agent"] = f'xython xythonnet/{version("xython")}'
    for url in urls:
        tokens = url.split(';')
        url = tokens.pop(0)
        for token in tokens:
            cmds = token.split('=')
            cmd = cmds[0]
            if cmd == 'verify':
                v = cmds[1]
                if v == '0':
                    verify=False
                elif v == '1':
                    verify=True
                else:
                    verify=cmds[1]
                options += f"verify={cmds[1]}"
            else:
                options += f"unknow={token}"
        if httpcount > 0:
            httpstate += "; "
        httpcount += 1
        # self.debug("\tDEBUG: http %s" % url)
        ts_http_start = time.time()
        try:
            r = requests.get(url, headers=headers, verify=verify)
            color = "green"
            hdata += f"&green {url} - OK\n\n"
            if r.status_code == need_httpcode:
                hdata += f"{r.status_code} {r.reason}\n"
            else:
                hdata += f"&red {r.status_code} {r.reason}\n"
            for header in r.headers:
                hdata += "%s: %s\n" % (header, r.headers[header])
            httpstate += "OK"
        except requests.exceptions.Timeout as e:
            color = "red"
            hdata += f"&red {url} - TIMEOUT\n"
            httpstate += r.reason
            httpstate += f"REASON={r.reason}"
        except requests.exceptions.RequestException as e:
            color = "red"
            if re.search('Connection refused', str(e)):
                httpstate += 'Connection refused'
                hdata += f"&red {url} - Connection refused\n"
            else:
                # TODO find something better to put readble error message
                emsg = str(e).replace(": ", ":<br>")
                hdata += f"&red {url} - KO<br>\n{emsg}\n"
                httpstate += "KO"
        except requests.exceptions.ConnectionError as e:
            color = "red"
            if re.search('Connection refused', str(e)):
                httpstate += 'Connection refused'
                hdata += f"&red {url} - Connection refused\n"
            else:
                hdata += f"&red {url} - KO\n"
                httpstate += "KO"
        ts_http_end = time.time()
        hdata += f"\nSeconds: {ts_http_end-ts_http_start}\n\n"
        if options != "":
            hdata += f"xython options: {options}\n"
    now = time.time()
    fdata = f"{xytime(now)}: {httpstate}\n"
    dret = {}
    dret["hostname"] = hostname
    dret["color"] = color
    dret["txt"] = fdata + hdata
    dret["type"] = 'http'
    return dret


@app.task
def dossh(hostname, port):
    ts_start = time.time()
    color = "green"
    try:
        s_ssh = socket.socket()
        s_ssh.connect((hostname, port))
        buf = s_ssh.recv(1024)
        banner = buf.decode("UTF8")
        s_ssh.close()
    except ConnectionError:
        color = "red"
        banner = "Failed to connect"
    except OSError as error:
        color = "red"
        banner = str(error)
    if color != 'red' and not re.search("OpenSSH", banner):
        color = 'red'
        banner = f"{banner} is not openssh"
    sbuf = f"{xytime(ts_start)} ssh ok\n\n"
    # TODO
    sbuf += f"Service ssh on {hostname}:{port} is OK (up)\n\n"
    sbuf += f"{banner}\n\n"
    sbuf += f"Seconds: {time.time() - ts_start}\n"
    dret = {}
    dret["hostname"] = hostname
    dret["color"] = color
    dret["txt"] = sbuf
    dret["type"] = 'ssh'
    return dret
