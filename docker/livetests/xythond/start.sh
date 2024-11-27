#!/bin/sh

/etc/init.d/redis-server start || exit $?

/etc/init.d/xython-celery start || exit $?
service --status-all

a2enconf xython || exit $?
/etc/init.d/apache2 start || exit $?

openssl req -x509 -newkey rsa:4096 -keyout /etc/xython/xython.key -out /etc/xython/xython.crt -sha256 -days 3650 -nodes -subj "/C=FR/ST=France/L=Paris/O=xython/OU=tests/CN=xython"

sed -i 's,^#,,' /etc/xython/xython.cfg
chgrp xython /etc/xython/xython*
chmod 640 /etc/xython/xython.key
ls -l /etc/xython

cat /etc/xython/xython.cfg

#xythond -x 2 --debug --etcdir /etc/xython/ -D --wwwdir /var/lib/xython/www
#echo $?
echo "DEBUG: start xythond"
/etc/init.d/xythond start || exit $?
#sudo /usr/bin/xython-client-looper.sh

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

cd /tests
pytest livetest.py

echo "DEBUG: get memory page"
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=$(hostname)&SERVICE=memory" -O memory.html
grep -q 'Real/Physical' memory.html
if [ $? -eq 0 ];then
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
cat conn.html
echo "DEBUG: everything is ok"
exit 0
sleep 365d
