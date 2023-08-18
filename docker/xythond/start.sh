#!/bin/sh

sudo /etc/init.d/redis-server start || exit $?

/etc/init.d/xython-celery start || exit $?
sudo service --status-all

sudo a2enconf xython || exit $?
sudo /etc/init.d/apache2 start || exit $?

sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/xython/xython.key -out /etc/xython/xython.crt -sha256 -days 3650 -nodes -subj "/C=FR/ST=France/L=Paris/O=xython/OU=tests/CN=xython" || exit $?

sudo sed -i 's,^#,,' /etc/xython/xython.cfg
sudo chgrp xython /etc/xython/xython*
sudo chmod 640 /etc/xython/xython.key
ls -l /etc/xython

cat /etc/xython/xython.cfg
/usr/bin/xython-tlsd --quit 5

sudo /etc/init.d/xython-tlsd start || exit $?
ps aux |grep xython-tlsd

sudo /etc/init.d/xythond start || exit $?
# wait for xythond to generate files
sleep 60
cd /tmp
wget http://127.0.0.1/xython/ || exit $?
wget http://127.0.0.1/xython/nongreen.html || exit $?
exit 0
