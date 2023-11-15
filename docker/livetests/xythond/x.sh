#!/bin/sh

DAEMON_ARGS="--etcdir /etc/xython/ -D --wwwdir /var/lib/xython/www"

/usr/bin/xythond $DAEMON_ARGS >/tmp/xython.debug 2>&1
