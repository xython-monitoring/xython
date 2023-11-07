#!/bin/sh

while [ true ];
do
	/usr/bin/xython-client.sh || exit $?
	sleep 120
done
