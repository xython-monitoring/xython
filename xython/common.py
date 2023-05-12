"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import time
import re
import sys
from datetime import datetime
from pytz import timezone


# Xymon use a format for day number not availlable on python
def xytime(ts):
    date = datetime.fromtimestamp(ts, timezone('Europe/Paris'))
    first = date.strftime("%a %b %d").replace(" 0", ' ')
    last = date.strftime(" %H:%M:%S %Y")
    return first + last


def xytime_(ts):
    date = datetime.fromtimestamp(ts, timezone('Europe/Paris'))
    first = date.strftime("%a_%b_%d").replace("_0", '_')
    last = date.strftime("_%H:%M:%S_%Y")
    return first + last


def xyts(sts, tz):
    sts = re.sub(r' ([0-9]) ', r' 0\1 ', sts)
    date = datetime.strptime(sts, "%a %b %d %H:%M:%S %Y")
    if tz is not None:
        date = date.replace(tzinfo=timezone(tz))
    return date.timestamp()


def xyts_(sts, tz):
    sts = re.sub(r'_([0-9])_', r'_0\1_', sts)
    date = datetime.strptime(sts, "%a_%b_%d_%H:%M:%S_%Y")
    if tz is not None:
        date = date.replace(tzinfo=timezone(tz))
    return date.timestamp()


DAYS_IN_S = 60 * 60 * 24


# show the duration in days/hours of a TS until now
def xydhm(ts, now):
    if now - ts < 60:
        return "0m"
    buf = ""
    diff = now - ts
    days = int(diff // DAYS_IN_S)
    if days > 0:
        buf += f"{days}d "
        diff -= days * DAYS_IN_S
    hours = int(diff // (60 * 60))
    if hours > 0:
        buf += f"{hours}h "
        diff -= hours * 60 * 60
    mins = int(diff // 60)
    if mins > 0:
        buf += f"{mins}m"
    return buf.rstrip(" ")


COLORS = ["purple", "red", "green", "yellow", "clear", "blue"]


def gcolor(color):
    if color in ['re', 'red']:
        return 'red'
    if color in ['gr', 'green']:
        return 'green'
    if color in ['cl', 'clear']:
        return 'clear'
    if color in ['ye', 'yellow']:
        return 'yellow'
    if color in ['bl', 'blue']:
        return 'blue'
    if color in ['pu', 'purple']:
        return 'purple'
    print("ERROR: gcolor: unknow color %s" % color)
    return 'purple'


def setcolor(colortry, oldcolor):
    if colortry == 'red':
        return 'red'
    if oldcolor in ['green', 'clear']:
        return colortry
    return oldcolor


# return gif from color
def gif(color, ts):
    now = time.time()
    if ts + 60 > now:
        return "%s-recent.gif" % color
    return "%s.gif" % color


def tokenize(line):
    tokens = []
    line = re.sub(r"\s*=\s*", '=', line)
    a = 0
    while len(line) > 0 and a < 10:
        a += 1
        if line[0] == '"':
            sline = line.split('"')
            tok = sline.pop(0)
            tok = sline.pop(0)
            line = '"'.join(sline)
            line = re.sub("^ ", '', line)
        else:
            sline = line.split(' ')
            # should be only ''
            tok = sline.pop(0)
            line = ' '.join(sline)
        tokens.append(tok)
    return tokens


# return a value in seconds optionnaly postfixed with a mhdw
def xydelay(s):
    try:
        pfix = s[-1]
        if pfix in ['m', 'h', 'd', 'w']:
            v = s.rstrip(s[-1])
            if pfix == 'm':
                return int(v) * 60
            if pfix == 'h':
                return int(v) * 60 * 60
            if pfix == 'd':
                return int(v) * 60 * 60 * 24
            if pfix == 'w':
                return int(v) * 60 * 60 * 24 * 7
            print("UNREACHABLE")
        return int(s)
    except ValueError:
        print(f"ERROR: invalid delay value {s}")
        return None
