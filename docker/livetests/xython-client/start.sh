#!/bin/sh

hostname |grep -q tls
if [ $? -eq 0 ];then
	echo "DEBUG: enable TLS"
	sed -i 's,#USE_TLS=0,USE_TLS=1,' /etc/xython/xython-client.cfg
	sed -i 's,#XYTHON_PORT=1984,XYTHON_PORT=1985,' /etc/xython/xython-client.cfg
	sed -i 's,#CAFILE=/etc/xython/ca.crt,CAFILE=/tmp/xython.crt,' /etc/xython/xython-client.cfg

	sleep 10
	wget http://xython-server/ca.crt -O /tmp/xython.crt

fi

hostname |grep -q openssl
if [ $? -eq 0 ];then
	echo "TLS_MODE=openssl" >> /etc/xython/xython-client.cfg
fi

hostname |grep -q curl
if [ $? -eq 0 ];then
	echo "DEBUG: download apache2 certificate"
	#curl -k -w '%{certs}' https://xython-server > /tmp/xython.crt
	#wget -q http://xython-server/apache.crt -O /tmp/xython.crt
	echo "=================================================================="
	echo "=================================================================="
	cat /tmp/xython.crt
	echo "=================================================================="
	echo "=================================================================="
fi

cat /etc/xython/xython.cfg

echo "DEBUG: start xython-client"
/etc/init.d/xython-client start || exit $?

echo "=================================================================="
echo "=================================================================="

sleep 15
echo "DEBUG: running xython-client at hand"
/usr/bin/xython-client.sh -d || exit $?

echo "DEBUG: check xython-client is still here" 
ps aux |grep xython-client
ls -l /run/xython-client

sleep 5

echo "DEBUG: test page index"
wget http://xython-server/xython/ || exit $?

echo "DEBUG: verify client appear"
wget "http://xython-server/xython-cgi/xythoncgi.py?HOST=$(hostname)&SERVICE=disk" -O /tmp/disk.out || exit $?
grep -q Filesystem /tmp/disk.out
if [ $? -ne 0 ];then
	cat /tmp/disk.out
	exit 1
fi

echo "DEBUG: everything is ok"
exit 0
