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
from xython.common import setcolor
from xython.common import xytime

from datetime import datetime

# TODO permit to configure localhost
app = Celery('tasks', backend='redis://localhost', broker='redis://localhost')


@app.task
def ping(hostname, t, doipv4, doipv6):
    ts_start = time.time()
    dret = {}
    dret["type"] = 'conn'
    dret["column"] = 'conn'
    dret["hostname"] = hostname
    dret["txt"] = ""
    dret["color"] = 'green'

    env = os.environ
    env["LANG"] = 'C'
    env["LC_ALL"] = 'C'
    if not doipv4 and not doipv6:
        ret = subprocess.run(["ping", "-c", "1", t], capture_output=True)
        if ret.returncode != 0:
            dret["color"] = 'red'
        hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
        dret["txt"] += hdata
    if doipv4:
        ret = subprocess.run(["ping", "-4", "-c", "1", t], capture_output=True)
        if ret.returncode != 0:
            dret["color"] = 'red'
        hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
        dret["txt"] += hdata
    if doipv6:
        ret = subprocess.run(["ping", "-6", "-c", "1", t], capture_output=True)
        if ret.returncode != 0:
            dret["color"] = 'red'
        hdata = ret.stdout.decode("UTF8") + ret.stderr.decode("UTF8")
        dret["txt"] += hdata
    test_duration = time.time() - ts_start
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    dret["timing"] = test_duration
    return dret


@app.task
def dohttp(hostname, urls, column):
    ts_start = time.time()
    color = "green"
    hdata = ""
    httpstate = ""
    httpcount = 0
    for url in urls:
        options = ""
        check_content = None
        verify = True
        timeout = 30
        headers = {}
        headers["User-Agent"] = f'xython xythonnet/{version("xython")}'
        need_httpcode = 200
        hdata += f'<fieldset><legend>{url}</legend>'
        print(f'DEBUG: dohttp: check {url}')
        tokens = url.split(';')
        url = tokens.pop(0)
        for token in tokens:
            cmds = token.split('=')
            cmd = cmds[0]
            if cmd == 'timeout':
                timeout = int(cmds[1])
                options += f"timeout={cmds[1]}"
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
                check_content = cmds[1].replace('[[:space:]]', '\s')
            elif cmd == 'httpcode':
                # TODO check it is an integer or regex
                need_httpcode = cmds[1]
            else:
                options += f"unknow={token}"
        if httpcount > 0:
            httpstate += "; "
        httpcount += 1
        certinfo = None
        # self.debug("\tDEBUG: http %s" % url)
        ts_http_start = time.time()
        try:
            r = requests.get(url, headers=headers, verify=verify, timeout=timeout, stream=True)
            if verify and 'https' in url:
                #cert = r.raw.connection.sock.getpeercert()
                certinfo = show_cert(r.raw.connection.sock, hostname)
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
                    hdata += f'&green pattern {check_content} found\n'
                else:
                    color = "red"
                    hdata += f'&red pattern {check_content} not found\n'
        except requests.exceptions.Timeout as e:
            color = "red"
            hdata += f"&red {url} - TIMEOUT\n"
            httpstate += "Timeout"
            #httpstate += r.reason
            #httpstate += f"REASON={r.reason}"
        except requests.exceptions.RequestException as e:
            color = "red"
            if re.search('Connection refused', str(e)):
                httpstate += 'Connection refused'
                hdata += f"&red {url} - Connection refused\n"
            else:
                # TODO find something better to put readable error message
                emsg = str(e).replace(": ", ":<br>")
                hdata += f"&red {url} - KO<br>\n{emsg}\n"
                httpstate += "KO"
#        except requests.exceptions.ConnectionError as e:
#            color = "red"
#            if re.search('Connection refused', str(e)):
#                httpstate += 'Connection refused'
#                hdata += f"&red {url} - Connection refused\n"
#            else:
#                hdata += f"&red {url} - KO\n"
#                httpstate += "KO"
        if certinfo:
            hdata += certinfo + "\n\n"
        if options != "":
            hdata += f"xython options: {options}\n"
        hdata += f'</fieldset><br>'
    now = time.time()
    fdata = f"{xytime(now)}: {httpstate}\n"
    test_duration = now - ts_start
    dret = {}
    dret["hostname"] = hostname
    dret["color"] = color
    dret["txt"] = fdata + hdata
    dret["timing"] = test_duration
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    dret["type"] = 'http'
    dret["column"] = 'http'
    return dret


def hex_to_binary(hs):
    #print("====================")
    hexs = ""
    i = 0
    while i < len(hs):
        c = hs[i]
        #print(f"DEBUG: current {c} i={i} len={len(hs)}")
        if c == '\\':
            if i + 1 >= len(hs):
                return None
            C = hs[i + 1]
            if C == 'x':
                if i + 3 >= len(hs):
                    return None
                v = hs[i+2:i+4]
                #print(f"DEBUG: value is {v}")
                hexs += f'{v} '
                i += 4
                continue
            elif C == 'r':
                hexs += "0D "
            elif C == 'n':
                hexs += "0A "
            elif C == 't':
                hexs += "09 "
            else:
                # TODO
                print(f"DEBUG: invalid {C}")
                return None
            i += 2
        else:
            hexs += f'{ord(c):x} '
            i += 1
    #print(f"DEBUG: final {hexs}")
    #print(f"DEBUG: final {bytes.fromhex(hexs)}")
    #print(f"DEBUG: final {bytes.fromhex(hexs).decode('UTF8')}")
    return bytes.fromhex(hexs)

# compare binary b and xython protocol binary format e
def hex_compare(b, e):
    #print("==========================")
    bh = hex_to_binary(e)
    #print(f"DEBUG: compare {bh} and {b}")
    # reduce lengh of b
    b = b[:len(bh)]
    #print(f"DEBUG: compare {bh} and {b}")
    if bh == b:
        return True
    return False

# https://stackoverflow.com/questions/6464129/certificate-subject-x-509
def get_cn(t):
    r = ""
    unk = ""
    for p in t:
        #if len(p) > 1:
        #    unk += "length "
        # TODO: does this can exists ?
        if p[0][0] == 'countryName':
            r += f"/C={p[0][1]}"
            continue
        if p[0][0] == 'stateOrProvinceName':
            r += f"/ST={p[0][1]}"
            continue
        if p[0][0] == 'organizationName':
            r += f"/O={p[0][1]}"
            continue
        if p[0][0] == 'commonName':
            r += f"/CN={p[0][1]}"
            continue
        if p[0][0] == 'localityName':
            r += f"/L={p[0][1]}"
            continue
        if p[0][0] == 'organizationalUnitName':
            r += f"/OU={p[0][1]}"
            continue
        if p[0][0] == 'organizationIdentifier':
            r += f"/OI={p[0][1]}"
            continue
        if p[0][0] == 'serialNumber':
            r += f"/SN={p[0][1]}"
            continue
        if p[0][0] == 'surname':
            r += f"/SN={p[0][1]}"
            continue
        unk += str(p)
        print(f"UNK={p}")
    ret = {}
    ret["unk"] = unk
    ret["name"] = r
    return ret

def show_cert(ssock, hostname):
    #print(f"DEBUG: show_cert for {hostname}")
    cert = ssock.getpeercert()
    if 'subject' not in cert:
        print("===================================")
        print("ERROR no subject")
        print(f"cert={cert}")
        return "Failed to get certificate for {hostname}"
    else:
        ret = get_cn(cert['subject'])
    if "name" not in ret:
        return f"Failed to get certificate for {hostname}"
    certinfo = f"Server certificate:\n\tSubject: {ret['name']}\n"
    certinfo += f"\tstart date: {cert['notBefore']}\n"
    certinfo += f"\texpire date:{cert['notAfter']}\n"
    ret = get_cn(cert['issuer'])
    certinfo += f"\tissuer:{ret['name']}\n"
    now = time.time()
    date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    expire =  date.timestamp()
    certinfo += f"expire in {(expire - now) / 86400} days\n"
    # TODO key size
    # TODO signature used
    # TODO cipher used

    return certinfo

def do_generic_proto_ssl(hostname, address, protoname, port, url, p_send, p_expect, p_options):
    ts_start = time.time()
    dret = {}
    dret["color"] = 'red'
    dret['column'] = protoname
    thostname = hostname
    tokens = url.split(':')
    i = 1
    verify = ssl.CERT_REQUIRED
    while i < len(tokens):
        option = tokens[i]
        print(f"DEBUG: generic proto ssl: check {option}")
        if tokens[i].isdigit():
            port = int(tokens[i])
        elif tokens[i][0:7] == 'column=':
            hs = tokens[i].split('=')
            dret['column'] = hs[1]
        elif tokens[i][0:7] == 'verify=':
            verify = ssl.CERT_NONE
            print(f"DEBUG: no certificate check for {thostname}")
        elif tokens[i][0:9] == 'hostname=':
            hs = tokens[i].split('=')
            thostname = hs[1]
        i += 1

    print(f"GENERIC TLS PROTOCOLS addr={address} port={port} proto={protoname} url={url} thostname={thostname}")

    try:
        context = ssl.create_default_context()
        context.check_hostname = not (verify == ssl.CERT_NONE)
        context.verify_mode = verify
        sock = socket.create_connection((address, port))
        ssock = context.wrap_socket(sock, server_hostname=thostname)
        if p_send:
            if '\\x' in p_send:
                ssock.write(hex_to_binary(p_send))
            else:
                ssock.write(p_send.encode("UTF8"))
        if p_expect or (p_options is not None and 'banner' in p_options):
            #print("DEBUG: we have banner")
            buf = ssock.read(1024)
            banner = buf.decode("UTF8")
            #print(f"DEBUG banner={banner}")
        if p_expect:
            if '\\x' in p_send:
                if hex_compare(buf, p_expect):
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nbinary banner ok\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nbinary banner ko wanted {p_expect} got {buf}\n\n"
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
        if context.check_hostname:
            dret["txt"] += show_cert(ssock, hostname) + "\n\n"
        else:
            dret["txt"] += "Cannot test certificate since verify=0\n\n"
    except socket.gaierror as e:
        dret["txt"] = f"Service {protoname} on {hostname} is KO\n\n{str(e)}n\n"
    except ssl.SSLCertVerificationError as e:
        dret["txt"] = f"Service {protoname} on {hostname} is KO\n\n{str(e)}\n\n"
    except ConnectionRefusedError:
        dret["txt"] = "Connection refused\n\n"
    except OSError as e:
        # errno 113 No route to host
        dret["txt"] = str(e) + "\n\n"
    dret["txt"] += f"\nSeconds: {time.time() - ts_start}\n"
    print(f"GENERIC TLS PROTOCOLS addr={address} port={port} proto={protoname} url={url} thostname={thostname} ret={dret}")
    return dret

@app.task
def do_generic_proto(hostname, address, protoname, port, urls, p_send, p_expect, p_options):
    ts_start = time.time()
    dret = {}
    dret["hostname"] = hostname
    dret["type"] = protoname
    dret["column"] = protoname
    dret["color"] = 'green'
    dret["txt"] = ""
    for url in urls:
        if p_options and "ssl" in p_options:
            ret = do_generic_proto_ssl(hostname, address, protoname, port, url, p_send, p_expect, p_options)
        else:
            ret = do_generic_proto_notls(hostname, address, protoname, port, url, p_send, p_expect, p_options)
        dret["color"] = setcolor(ret["color"], dret["color"])
        dret["txt"] += ret["txt"]
        if 'column' in ret:
            dret["column"] = ret["column"]
    test_duration = time.time() - ts_start
    dret["txt"] += f"\nSeconds: {test_duration}\n"
    dret["timing"] = test_duration
    return dret

def do_generic_proto_notls(hostname, address, protoname, port, url, p_send, p_expect, p_options):
    dret = {}
    dret["color"] = 'red'
    dret['column'] = protoname

    tokens = url.split(':')
    print(f"DEBUG: {url} {tokens} {len(tokens)}")
    i = 1
    while i < len(tokens):
        option = tokens[i]
        print(f"DEBUG: generic proto notls: check {option}")
        if tokens[i].isdigit():
            port = int(tokens[i])
        i += 1

    try:
        s = socket.socket()
        s.connect((address, port))
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
                if hex_compare(buf, p_expect):
                    dret["color"] = 'green'
                    dret["txt"] = f"Service {protoname} on {hostname} is OK\n\nbinary banner ok\n\n"
                else:
                    dret["color"] = 'red'
                    dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nbinary banner ko GOT {buf}\n\n"
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
    except ConnectionError as e:
        dret["txt"] = f"Service {protoname} on {hostname} is ko\n\nFailed to connect to {address} {str(e)}\n\n"
    except OSError as error:
        dret["txt"] = f"Servide {protoname} on {hostname} is ko\n\n" + str(error) + "\n\n"
    return dret
