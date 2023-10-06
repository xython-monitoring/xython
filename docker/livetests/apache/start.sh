#!/bin/sh

/etc/init.d/apache2 start || exit $?

tail -F /var/log/apache2/*log

sleep 365d
