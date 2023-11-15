#!/bin/sh

/etc/init.d/xymon-client start || exit $?
sleep 365d
