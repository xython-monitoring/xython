#!/bin/sh

NOACT=0
DEBUG=0
XYTHON_SRV=127.0.0.1
XYTHON_PORT=1984
XYTHON_TLS_PORT=1985
USE_TLS=0
FORCE_TLS=0
CAFILE=""
NC_OPTS=""
# either systemd or init script should create it
XYTHON_TMP="/run/xython-client"

debug()
{
	if [ $DEBUG -ge 1 ];then
		echo "$*"
	fi
}

# find "$1=xx" in file $2 and set V to xx
get_value() {
	if [ ! -e "$2" ];then
		return 1
	fi
	debug "DEBUG: seek $1 in $2"
	V=$(grep -o "^$1=[\"a-z0-9A-Z_: \.-]*" "$2" | cut -d= -f2 | sed 's,",,g')
	if [ -z "$V" ];then
		return 1
	fi
	debug "DEBUG: $1=${V}"
	return 0
}

while [ $# -ge 1 ];
do
case $1 in
-d)
	shift
	DEBUG=1
;;
-n)
	shift
	NOACT=1
;;
--tls)
	shift
	# for testing in cmdline
	FORCE_TLS=1
;;
*)
	echo "ERROR: unknow argument"
	exit 0
;;
esac
done

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
	debug "DEBUG: from $F got XYMSRV=$XYMSRV"
	debug "DEBUG: from $F got XYMSERVERS=$XYMSERVERS"
	debug "DEBUG: from $F got XYMONSERVERS=$XYMONSERVERS"
fi

# XYMSRV in /etc/xymon-client/xymonclient.cfg
F='/etc/xymon-client/xymonclient.cfg'
if [ -e /etc/xymon-client/xymonclient.cfg ];then
	XYMSRV=$(grep -o '^XYMSRV=["a-z0-9A-Z_\.-]*' /etc/xymon-client/xymonclient.cfg | cut -d= -f2 | sed 's,",,g')
	XYMSERVERS=$(grep -o '^XYMSERVERS=["a-z0-9A-Z_ \.-]*' /etc/xymon-client/xymonclient.cfg | cut -d= -f2 | sed 's,",,g')
	# TODO XYMSERVERS=
	if [ -z "$XYMSRV" -o "$XYMSRV" == '0.0.0.0' ];then
		echo "TODO"
		exit 1
	fi
	debug "DEBUG: from $F got XYMSRV=$XYMSRV"
	XYTHON_SRV=$XYMSRV
	debug "DEBUG: from $F got XYMSERVERS=$XYMSERVERS"
fi

# xython conf has more priority than xymon
get_value USE_TLS /etc/xython/xython-client.cfg && USE_TLS=$V
get_value XYTHON_SRV /etc/xython/xython-client.cfg && XYTHON_SRV=$V
get_value XYTHON_PORT /etc/xython/xython-client.cfg && XYTHON_PORT=$V
get_value XYTHON_TLS_PORT /etc/xython/xython-client.cfg && XYTHON_TLS_PORT=$V
get_value CAFILE /etc/xython/xython-client.cfg && CAFILE="-CAfile $V"

# check if the address is IPV6
# TODO do not handle yet a DNS resolving to ipv6
echo "$XYTHON_SRV" |grep -q ':'
if [ $? -eq 0 ];then
	NC_OPTS="-6"
fi

if [ $NOACT -ge 1 ];then
	echo "FINAL: $XYTHON_SRV $XYTHON_PORT"
	exit 0
fi

case $USE_TLS in
0)
	debug "DEBUG: NO TLS"
	# TODO there a re multiple version of netcat
	if [ -x /usr/bin/nc ];then
		debug "DEBUG: nc on $XYTHON_SRV $XYTHON_PORT"
		xython-client 2>$XYTHON_TMP/xython.err >$XYTHON_TMP/xython.msg || exit $?
		# TODO send error as part of message
		cat $XYTHON_TMP/xython.msg | nc $NC_OPTS -w 5 -q 5 $XYTHON_SRV $XYTHON_PORT > $XYTHON_TMP/logfetch.$(hostname).cfg
		exit $?
	fi
;;
1)
	# TODO if no openssl, fall back to something else
	# TODO -servername
	xython-client 2>$XYTHON_TMP/xython.err >$XYTHON_TMP/xython.msg || exit $?
	cat $XYTHON_TMP/xython.msg | openssl s_client -quiet $CAFILE -connect $XYTHON_SRV:$XYTHON_TLS_PORT > $XYTHON_TMP/logfetch.$(hostname).cfg
	exit $?
;;
*)
	echo "ERROR"
	exit 1
;;
esac

exit 0
