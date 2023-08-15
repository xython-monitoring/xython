#!/bin/sh
	
XYTHONSRV=127.0.0.1
SERVER_PORT=12346
USE_TLS=0

#gentoo
#if [ -e /etc/conf.d/xymon-client ];then
#	echo ""
#fi

# debian in /etc/default/xymon-client
# XYMONSERVERS= CLIENTHOSTNAME=i
# on debian /etc/xymon/xymonclient.cfg
F='/etc/default/xymon-client'
if [ -e "$F" ];then
	echo "DEBUG: seek in $F"
	XYMSRV=$(grep -o '^XYMSRV=["a-z0-9A-Z_\.-]*' "$F" | cut -d= -f2 | sed 's,",,g')
	XYMSERVERS=$(grep -o '^XYMSERVERS=["a-z0-9A-Z_ \.-]*' "$F" | cut -d= -f2 | sed 's,",,g')
	XYMONSERVERS=$(grep -o '^XYMONSERVERS=["a-z0-9A-Z_ \.-]*' "$F" | cut -d= -f2 | sed 's,",,g')
	echo "$XYMSRV"
	echo "$XYMSERVERS"
	echo "$XYMONSERVERS"
fi

# XYMSRV in /etc/xymon-client/xymonclient.cfg
if [ -e /etc/xymon-client/xymonclient.cfg ];then
	XYMSRV=$(grep -o '^XYMSRV=["a-z0-9A-Z_\.-]*' /etc/xymon-client/xymonclient.cfg | cut -d= -f2 | sed 's,",,g')
	XYMSERVERS=$(grep -o '^XYMSERVERS=["a-z0-9A-Z_ \.-]*' /etc/xymon-client/xymonclient.cfg | cut -d= -f2 | sed 's,",,g')
	# TODO XYMSERVERS=
	if [ -z "$XYMSRV" -o "$XYMSRV" == '0.0.0.0' ];then
		echo "TODO"
		exit 1
	fi
	echo "$XYMSRV"
	echo "$XYMSERVERS"
fi

if [ -e /etc/xython/xxx ];then
	echo "TODO"
fi

case $USE_TLS in
0)
	# TODO there a re multiple version of netcat
	if [ -x /usr/bin/nc ];then
		fake_client | nc -w 5 -q 5 $XYTHONSRV $SERVERPORT
		exit $?
	fi
;;
1)
	# TODO if no openssl, fall back to something else
	# TODO -servername and -CAfile
	fake_client | openssl s_client -quiet -connect $XYTHONSRV:$SERVERPORT
	exit $?
;;
*)
	echo "ERROR"
;;
esac

exit 0
