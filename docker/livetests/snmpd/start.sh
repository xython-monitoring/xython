#!/bin/sh

/etc/init.d/snmpd start || exit $?

sleep 365d
