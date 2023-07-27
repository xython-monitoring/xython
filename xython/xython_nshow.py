#!/usr/bin/env python3

# ncurses xython overview

import pika
import sys
import curses
from curses import wrapper
import threading

L_RED = 1
L_GREEN = 2
L_BLUE = 3
L_WHITE = 4
L_CYAN = 5
L_YELLOW = 6

mall = []
hosts = {}
HOSTMAX = 0
columns = []

credentials = pika.PlainCredentials('xython', 'password')
connection = pika.BlockingConnection(pika.ConnectionParameters(host='127.0.0.1', port=5672, credentials=credentials))
channel = connection.channel()

channel.exchange_declare(exchange='xython-status', exchange_type='fanout')
result = channel.queue_declare(queue='', exclusive=True)
queue_name = result.method.queue
channel.queue_bind(exchange='xython-status', queue=queue_name)


def callback(ch, method, properties, body):
    #print(body.decode("UTF8"))
    msg = body.decode("UTF8")
    lines = msg.split('\n')
    data = ""
    i = 1
    while i < len(lines) - 1:
        data += lines[i]
        data += '\n'
        i += 1
    r = msg.split('/')[1]
    rr = r.split('|')
    host = rr[0]
    if host not in hosts:
        hosts[host] = {}
    col = rr[5]
    if col not in columns:
        columns.append(col)
        columns.sort()
    if col not in hosts[host]:
        hosts[host][col] = {}
    hosts[host][col]["color"] = rr[7]
    data.replace('<br>', '\n')
    hosts[host][col]["data"] = data
    #mall.append(body.decode("UTF8"))
    #sys.stdout.flush()


def pikathread():
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
    channel.start_consuming()


ct = threading.Thread(target=pikathread)
ct.start()


def xmain(stdscr):
    needexit = False
    curses.init_pair(L_RED, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(L_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(L_BLUE, curses.COLOR_BLUE, curses.COLOR_BLACK)
    curses.init_pair(L_WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(L_CYAN, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(L_YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    print("toto")
    mwin = None
    sx = 0
    sy = 0
    stdscr.timeout(50)
    overpad = curses.newpad(500, 500)
    pad = curses.newpad(500, 500)
    dwin = None
    owin = None
    while not needexit:
        shost = None
        scol = None
        rows, cols = stdscr.getmaxyx()
        if not mwin:
            mwin = curses.newwin(rows, cols)
        mwin.erase()
        mwin.addstr(0, 0, f"Test {cols}x{rows} Y={sy}/{len(hosts)}")
        HOSTMAX = 0
        for host in hosts:
            if len(host) > HOSTMAX:
                HOSTMAX = len(host)
        x = HOSTMAX + 1
        nc = 0
        overpad.erase()
        for col in columns:
            if sx == nc:
                overpad.addstr(0, x, col, curses.color_pair(L_YELLOW))
                scol = col
            else:
                overpad.addstr(0, x, col)
            x += len(col) + 2
            nc += 1
        y = 1
        nh = 0
        for host in hosts:
            x = 0
            if sy == nh:
                overpad.addstr(y, x, host, curses.color_pair(L_YELLOW))
                shost = host
            else:
                overpad.addstr(y, x, host)
            x = HOSTMAX + 1
            for col in columns:
                if col in hosts[host]:
                    color = hosts[host][col]["color"]
                    if color == "red":
                        overpad.addstr(y, x, 'R', curses.color_pair(L_RED))
                    elif color == "green":
                        overpad.addstr(y, x, 'G', curses.color_pair(L_GREEN))
                    elif color == "yellow":
                        overpad.addstr(y, x, 'Y', curses.color_pair(L_YELLOW))
                    elif color == "blue":
                        overpad.addstr(y, x, 'B', curses.color_pair(L_BLUE))
                    elif color == "purple":
                        overpad.addstr(y, x, 'P', curses.color_pair(L_CYAN))
                    else:
                        overpad.addstr(y, x, color)
                x += len(col) + 2
            y += 1
            nh += 1
        mwin.noutrefresh()
        if shost is not None and scol is not None:
            if scol in hosts[shost]:
                if "data" in hosts[shost][scol]:
                    data = hosts[shost][scol]["data"]
                    dwin = curses.newwin(rows - 1, cols - 1, y, 0)
                    dwin.box("|", "-")
                    dwin.noutrefresh()
                    pad.erase()
                    pad.addstr(0, 0, data)
                    pad.noutrefresh(0, 0, y + 1, 1, rows - 2, cols - 2)
        owin = curses.newwin(y + 2, cols - 1, 1, 0)
        owin.box("|", "-")
        owin.noutrefresh()
        if y > 1:
            overpad.noutrefresh(0, 0, 2, 2, y + 1, cols - 2)
        stdscr.noutrefresh()
        curses.doupdate()
        c = stdscr.getch()
        if c == 27 or c == ord('q'):
            needexit = True
            channel.stop_consuming()
            ct.join()
        if c == curses.KEY_UP:
            sy -= 1
        if c == curses.KEY_DOWN:
            sy += 1
        if sy < 0:
            sy = len(hosts) - 1
        if sy >= len(hosts):
            sy = 0
        if c == curses.KEY_LEFT:
            sx -= 1
        if c == curses.KEY_RIGHT:
            sx += 1
        if sx < 0:
            sx = len(columns) - 1
        if sx >= len(columns):
            sx = 0


wrapper(xmain)


sys.exit(0)
