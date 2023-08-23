#!/bin/sh

sudo /etc/init.d/redis-server start || exit $?

sudo a2enconf xython
sudo /etc/init.d/apache2 start || exit $?

sudo /etc/init.d/xython-celery start || exit $?

sudo /etc/init.d/xythond start || exit $?
sudo /etc/init.d/xython-client start || exit $?
sleep 120
cd /tmp
echo "DEBUG: tests index"
wget http://127.0.0.1/xython/ -O index.html -o result || exit $?
if [ $? -ne 0 ];then
	cat result
	exit 1
fi
echo "DEBUG: tests nongreen"
wget http://127.0.0.1/xython/nongreen.html -o result || exit $?
if [ $? -ne 0 ];then
	cat result
	exit 1
fi

echo "DEBUG: tests memory"
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=$(hostname)&SERVICE=memory" -O memory.html -o result
if [ $? -ne 0 ];then
	cat result
	exit 1
fi
grep -q 'Real/Physical' memory.html
if [ $? -ne 0 ];then
	echo "ERROR:"
	cat memory.html
fi

echo "DEBUG: stop client"
sudo /etc/init.d/xython-client stop || exit $
sudo sed -i 's,#USE_TLS=0,USE_TLS=1,' /etc/xython/xython-client.cfg
sudo sed -i 's,#XYTHON_PORT=1984,XYTHON_PORT=1985,' /etc/xython/xython-client.cfg
echo "DEBUG: start TLS client"
sudo /etc/init.d/xython-client start || exit $

echo "DEBUG: try to access non-existing xtrahosts"
# should not exists
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=xtrahosts&SERVICE=conn" -O conn.html -o result
if [ $? -ne 0 ];then
	cat result
	exit 1
fi
grep -q 'ERROR: no service' conn.html
if [ $? -ne 0 ];then
	exit 1
fi

echo "DEBUG: add xtrahosts"
echo "0.0.0.0 xtrahosts conn" >> /etc/xython/hosts.cfg
sleep 120

echo "DEBUG: try to access existing xtrahosts"
# should exists
wget "http://127.0.0.1/xython-cgi/xythoncgi.py?HOST=xtrahosts&SERVICE=conn" -O conn.html -o result
if [ $? -ne 0 ];then
	cat result
	exit 1
fi
#cat conn.html
grep -q 'ERROR: no service' conn.html
if [ $? -eq 0 ];then
	exit 1
fi
exit 0
