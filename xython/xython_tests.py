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
import ssl
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
def dohttp(hostname, urls, column):
    color = "green"
    hdata = ""
    httpstate = ""
    httpcount = 0
    options = ""
    for url in urls:
        check_content = None
        verify = True
        headers = {}
        headers["User-Agent"] = f'xython xythonnet/{version("xython")}'
        need_httpcode = 200
        print(f'DEBUG: check {url}')
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
            elif cmd == 'cont':
                check_content = cmds[1]
            elif cmd == 'httpcode':
                # TODO check it is an integer or regex
                need_httpcode = cmds[1]
            else:
                options += f"unknow={token}"
        if httpcount > 0:
            httpstate += "; "
        httpcount += 1
        # self.debug("\tDEBUG: http %s" % url)
        ts_http_start = time.time()
        try:
            r = requests.get(url, headers=headers, verify=verify)
            hdata += f"&green {url} - OK\n\n"
            scode = str(r.status_code)
            sneed = str(need_httpcode)
            rr = re.match(sneed, scode)
            if rr:
                hdata += f"&green {r.status_code} {r.reason}\n"
            else:
                color = "red"
                hdata += f"&red {r.status_code} {r.reason} (want code={need_httpcode})\n"
            for header in r.headers:
                hdata += "%s: %s\n" % (header, r.headers[header])
            httpstate += "OK"
            if check_content:
                content = r.content.decode('utf8')
                if re.search(check_content, content):
                    hdata += f'&green pattern {check_content} found in {content}'
                else:
                    hdata += f'&red pattern {check_content} not found in {content}'
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


def hex_to_binary(hs):
    hexs = ""
    i = 0
    while i < len(hs):
        if i + 4 > len(hs):
            return None
        header = hs[i:i+2]
        if header != '\\x':
            return None
        h = hs[i+2:i+4]
        hexs += h
        hexs += ' '
        i += 4
    return bytes.fromhex(hexs)

# compare binary b and e
def hex_compare(b, e):
    i = 0
    hexs = ""
    while i < len(e):
        if i + 4 > len(e):
            return None
        header = e[i:i+2]
        if header != '\\x':
            return None
        hexs += e[i+2:i+4]
        i += 4
    bh = bytes.fromhex(hexs)
    if bh == b:
        return True
    return False

def do_generic_proto_ssl(hostname, address, PP, port):
    ts_start = time.time()
    p_options = PP["options"]
    p_port = PP["port"]
    p_expect = PP["expect"]
    p_send = PP["send"]
    protoname = PP["protoname"]
    dret = {}
    dret["hostname"] = hostname
    dret["type"] = protoname
    dret["color"] = 'red'
    protoname = PP["protoname"]

    print(f"GENERIC TLS PROTOCOLS addr={address} port={p_port} proto={protoname}")

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((address, p_port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                if p_send:
                    if '\\x' in p_send:
                        ssock.write(hex_to_binary(p_send))
                    else:
                        ssock.write(p_send.encode("UTF8"))
                if p_expect or (p_options is not None and 'banner' in p_options):
                    buf = ssock.read(1024)
                    banner = buf.decode("UTF8")
                if p_expect:
                    if '\\x' in p_send:
                        if self.hex_compare(buf, p_expect):
                            dret["color"] = 'green'
                            dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nbinary banner ok\n\n"
                        else:
                            dret["color"] = 'red'
                            dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nbinary banner ko\n\n"
                    else:
                        if p_expect in banner:
                            dret["color"] = 'green'
                            dret["txt"] = f"Service {protoname} on {hostname} is OK\n{banner}\n\n"
                        else:
                            dret["color"] = 'red'
                            dret["txt"] = f"Service {protoname} on {hostname} is ko\n{banner}\n\nWanted {p_expect}\n\n"
                else:
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nconnected successfully on {address}\n"
    except socket.gaierror as e:
        dret["txt"] = f"Service {protoname} on {hostname} is KO\n\n{str(e)}n\n"
    except ssl.SSLCertVerificationError as e:
        dret["txt"] = f"Service {protoname} on {hostname} is KO\n\n{str(e)}\n\n"
    except ConnectionRefusedError:
        dret["txt"] = "connection refused\n\n"
    dret["txt"] += f"Seconds: {time.time() - ts_start}\n"
    return dret

@app.task
def do_generic_proto(hostname, address, PP, port):
    ts_start = time.time()
    p_options = PP["options"]
    if p_options and "ssl" in p_options:
        return do_generic_proto_ssl(hostname, address, PP, port)
    p_port = PP["port"]
    p_expect = PP["expect"]
    p_send = PP["send"]
    protoname = PP["protoname"]
    dret = {}
    dret["hostname"] = hostname
    dret["type"] = protoname
    dret["color"] = 'red'
    try:
        s = socket.socket()
        s.connect((address, p_port))
        if p_send:
            if '\\x' in p_send:
                s.send(hex_to_binary(p_send))
            else:
                s.send(p_send.encode("UTF8"))
        if p_expect or (p_options is not None and 'banner' in p_options):
            buf = s.recv(1024)
            banner = buf.decode("UTF8")
        if p_expect:
            if '\\x' in p_send:
                if self.hex_compare(buf, p_expect):
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nbinary banner ok\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nbinary banner ko\n\n"
            else:
                if p_expect in banner:
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n{banner}\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n{banner}\n\n"
        else:
            dret["color"] = 'green'
            dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nconnected successfully on {address}\n"
        s.close()
    except ConnectionError:
        dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nFailed to connect to {address}\n\n"
    except OSError as error:
        dret["txt"] = f"Servide {protoname} on {hostname} is ko\n\n" + str(error) + "\n\n"
    dret["txt"] += f"Seconds: {time.time() - ts_start}\n"
    return dret
