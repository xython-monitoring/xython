"""
    xython: a xymon monitoring replacement in python
    Copyright (C) 2023-2024 Corentin LABBE <clabbe.montjoie@gmail.com>
    SPDX-License-Identifier: GPL-2.0
"""

import logging
import time
import re
from datetime import datetime
from datetime import timedelta
from pytz import timezone


def xlog_error(message):
    print(message)
    logger = logging.getLogger('xython')
    logger.error(message)

# Xymon use a format for day number not availlable on python
def xytime(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    first = date.strftime("%a %b %d").replace(" 0", ' ')
    last = date.strftime(" %H:%M:%S %Y")
    return first + last


def xytime_(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    first = date.strftime("%a_%b_%d").replace("_0", '_')
    last = date.strftime("_%H:%M:%S_%Y")
    return first + last


def xyts(sts, tz='Europe/Paris'):
    sts = re.sub(r' ([0-9]) ', r' 0\1 ', sts)
    date = datetime.strptime(sts, "%a %b %d %H:%M:%S %Y")
    date = timezone(tz).localize(date)
    return date.timestamp()
    return date.astimezone(timezone('utc')).timestamp()


def xyts_(sts, tz='Europe/Paris'):
    sts = re.sub(r'_([0-9])_', r'_0\1_', sts)
    date = datetime.strptime(sts, "%a_%b_%d_%H:%M:%S_%Y")
    date = timezone(tz).localize(date)
    return date.timestamp()


def xyevent_to_ts(sts, tz='Europe/Paris'):
    try:
        date = datetime.strptime(sts, "%Y/%m/%d@%H:%M:%S")
    except ValueError:
        xlog_error(f"ERROR: xyevent_to_ts: Invalid TS {sts}")
        return None
    date = timezone(tz).localize(date)
    return date.timestamp()


def xyevent(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    first = date.strftime("%Y/%m/%d")
    last = date.strftime("@%H:%M:%S")
    return first + last


def event_thisyear(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    return f"{date.year}/01/01@00:00:00"


def event_lastyear(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    return f"{date.year - 1}/01/01@00:00:00"


def event_thismonth(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    return f"{date.year}/{date.month:02}/01@00:00:00"


def event_lastmonth(ts, tz='Europe/Paris'):
    date = datetime.fromtimestamp(ts, timezone(tz))
    lm = date.replace(day=1) - timedelta(days=1)
    return f"{lm.year}/{lm.month:02}/01@00:00:00"


def event_thisweek(ts):
    date = datetime.fromtimestamp(ts, timezone('Europe/Paris'))
    w = date.weekday()
    lm = date.date() - timedelta(days=w)
    return f"{lm.year}/{lm.month:02}/{lm.day:02}@00:00:00"


def event_lastweek(ts):
    date = datetime.fromtimestamp(ts, timezone('Europe/Paris'))
    w = date.weekday() + 7
    lm = date.date() - timedelta(days=w)
    return f"{lm.year}/{lm.month:02}/{lm.day:02}@00:00:00"


def event_yesterday(ts):
    date = datetime.fromtimestamp(ts, timezone('Europe/Paris'))
    lm = date.date() - timedelta(days=1)
    return f"{lm.year}/{lm.month:02}/{lm.day:02}@00:00:00"


def event_today(ts):
    date = datetime.fromtimestamp(ts, timezone('Europe/Paris'))
    return f"{date.year}/{date.month:02}/{date.day:02}@00:00:00"


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
    if color == '-':
        return 'unknown'
    print("ERROR: gcolor: unknow color %s" % color)
    return 'purple'


def setcolor(colortry, oldcolor):
    if colortry == 'red':
        return 'red'
    if colortry == 'clear':
        return oldcolor
    if oldcolor in ['green', 'clear']:
        return colortry
    return oldcolor


# return gif from color
def gif(color, ts, isack=False):
    if color == '-':
        color = 'unknown'
    now = time.time()
    if isack:
        return f"{color}-ack.gif"
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
            return int(v) * 60 * 60 * 24 * 7
            # print("UNREACHABLE")
        return int(s)
    except ValueError:
        print(f"ERROR: invalid delay value {s}")
        return None


def is_valid_hostname(hostname):
    if hostname is None:
        return False
    # should not start or end with .
    if hostname[0] == '.' or hostname[-1] == '.':
        return False
    return re.match("^[a-zA-Z0-9_.-]*$", hostname)


def is_valid_column(column):
    if column is None:
        return False
    return re.match("^[a-zA-Z0-9_-]*$", column)


def is_valid_color(color):
    return color in ['green', 'yellow', 'red', 'purple', 'blue', 'clear']
