#!/bin/bash

/etc/init.d/redis-server start || exit $?

/etc/init.d/xython-celery start || exit $?
service --status-all

echo "DEBUG: Generate crt/key for xython"
DOMAIN=xython-server
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -subj "/C=FR/ST=France/L=Paris/O=xython/OU=tests/OU=pytest/OI=xython/CN=xython PKI/serialNumber=1/SN=tests/emailAddress=tests@xython.fr/DC=tests/PC=75000/" -out ca.crt

openssl req -newkey rsa:2048 -nodes -keyout $DOMAIN.key -subj "/C=FR/ST=France/L=Paris/O=xython/CN=$DOMAIN" -out $DOMAIN.csr
openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN") -days 3650 -in $DOMAIN.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $DOMAIN.crt
#openssl req -x509 -newkey rsa:4096 -keyout /etc/xython/xython.key -out /etc/xython/xython.crt -sha256 -days 3650 -nodes -subj "/C=FR/ST=France/L=Paris/O=xython/OU=tests/CN=xython"

cp $DOMAIN.key /etc/xython/xython.key
cp $DOMAIN.crt /etc/xython/xython.crt

# copy CA for client to download it
#cp /etc/xython/xython.crt /var/www/html/
#cp /etc/ssl/certs/ssl-cert-snakeoil.pem /var/www/html/apache.crt
cp ca.crt /var/www/html/
cat /etc/xython/xython.key > /etc/ssl/private/ssl-cert-snakeoil.key
cat /etc/xython/xython.crt > /etc/ssl/certs/ssl-cert-snakeoil.pem

a2enmod ssl
a2enconf xython || exit $?
a2ensite default-ssl || exit $?
/etc/init.d/apache2 start || exit $?

echo "DEBUG: Verify apache2 is started"
ss -tlpn

sed -i 's,^#,,' /etc/xython/xython.cfg
echo "DEBUG=1" >> /etc/xython/xython.cfg
chgrp xython /etc/xython/xython*
chmod 640 /etc/xython/xython.key
ls -l /etc/xython

cat /etc/xython/xython.cfg

echo "0.0.0.0 client-tls-openssl0 # conn" >> /etc/xython/hosts.cfg
echo "0.0.0.0 client-tls-curl0 # conn" >> /etc/xython/hosts.cfg
echo "0.0.0.0 client0 # conn" >> /etc/xython/hosts.cfg

#xythond -x 2 --debug --etcdir /etc/xython/ -D --wwwdir /var/lib/xython/www
#echo $?

echo "DEBUG: start xythond"
/etc/init.d/xythond start || exit $?
#sudo /usr/bin/xython-client-looper.sh
sleep 5
echo "DEBUG: verify xythond is started"
ps aux |grep xython
ss -tlpn
ss -tlpn |grep -q 1984
if [ $? -ne 0 ];then
	echo "ERROR: xython port is not open"
	cat /var/log/xython/*
	exit 1
fi
ss -tlpn |grep -q 1985
if [ $? -ne 0 ];then
	echo "ERROR: xython TLS port is not open"
	cat /var/log/xython/*
	exit 1
fi

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
cd /tmp
echo "DEBUG: test page index"
wget http://127.0.0.1/xython/ || exit $?
echo "DEBUG: test page nongreen"
wget http://127.0.0.1/xython/nongreen.html || exit $?

echo "DEBUG: test page nongreen from https"
wget --no-check-certificate https://127.0.0.1/xython/nongreen.html || exit $?

cd /tests
pytest livetest.py

echo "DEBUG: get memory page"
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=$(hostname)&SERVICE=memory" -O memory.html
grep -q 'Real/Physical' memory.html
if [ $? -ne 0 ];then
	echo "ERROR: fail to find pattern in memory.html"
	cat memory.html
	exit 1
fi

echo "DEBUG: stop xython-client"
/etc/init.d/xython-client stop || exit $
sed -i 's,#USE_TLS=0,USE_TLS=1,' /etc/xython/xython-client.cfg
sed -i 's,#XYTHON_PORT=1984,XYTHON_PORT=1985,' /etc/xython/xython-client.cfg
echo "DEBUG: start xython-client with TLS"
/etc/init.d/xython-client start || exit $
sleep 10
echo "DEBUG: check xython-client is still here" 
ps aux |grep xython-client
ls -l /run/xython-client

echo "DEBUG: try to access non-existing xtrahosts"
# should not exists
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=xtrahosts&SERVICE=conn" -O conn.html -o result
grep -q 'ERROR: no service' conn.html
if [ $? -ne 0 ];then
	echo "ERROR: service conn for xtrahosts is present"
	cat conn.html
	cat /tmp/xython.debug
	exit 1
fi

echo "DEBUG: add xtrahosts"
echo "0.0.0.0 xtrahosts conn" >> /etc/xython/hosts.cfg
echo "DEBUG: wait 3 minutes"
sleep 180

echo "DEBUG: try to access existing xtrahosts"
# should exists
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=xtrahosts&SERVICE=conn" -O conn.html -o result
grep -q 'ERROR: no service' conn.html
if [ $? -eq 0 ];then
	cat conn.html
	echo "ERROR: service conn for xtrahosts is not present"
	exit 1
fi
grep -q 'Status Message received from xython-tests' conn.html
if [ $? -ne 0 ];then
	exit 1
fi

echo "DEBUG: everything is ok"

cat /var/log/xython/*

exit 0
sleep 365d
