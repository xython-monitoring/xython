#!/usr/bin/env python3

import pytest
import re
import requests

def test_allurl():
    url = "http://127.0.0.1/xython/xython.html"
    r = requests.get(url, timeout=30)
    assert r.status_code == 200
    data = r.content.decode('utf8')
    #ret = re.search('href="[a-zA-Z0-9_/=&;-\.]*', data, re.IGNORECASE)
    ret = re.findall('href="[^"]*', data, re.IGNORECASE)
    for surl in ret:
        if "javascript" in surl:
            continue
        if "/xython/help/" in surl:
            continue
        if "/xython-cgi/columndoc.sh?" in surl:
            continue
        if len(surl) < 7:
            continue
        surl = surl[6:]
        if surl in ["/xython-cgi/criticalview.sh", "/xython-cgi/eventlog.sh", "/xython-cgi/topchanges.sh", "/xython-cgi/report.sh", "/xython-cgi/snapshot.sh", "/xython-cgi/confreport.sh", "/xython-cgi/confreport-critical.sh", "/xython-cgi/hostgraphs.sh", "/xython-cgi/ghostlist.sh", "/xython-cgi/notifications.sh", "/xython-cgi/acknowledgements.sh", "/xython-cgi/findhost.sh", "/acknowledge.sh", "/enadis.sh", "/criticaleditor.sh"]:
            continue
        if surl[0] == '/':
            url = f"http://127.0.0.1{surl}"
            r = requests.get(url)
            print(f"DEBUG: test {surl} code={r.status_code}")
            assert r.status_code == 200
    url = "http://127.0.0.1/xython/nongreen.html"
    r = requests.get(url, timeout=30)
    assert r.status_code == 200
