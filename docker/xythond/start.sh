#!/bin/sh

sudo /etc/init.d/redis-server start || exit $?

/etc/init.d/xython-celery start
sudo service --status-all

sudo a2enconf xython || exit $?
sudo /etc/init.d/apache2 start || exit $?

./usr/bin/xython-tlsd -V

sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/xython/xython.key -out /etc/xython/xython.crt -sha256 -days 3650 -nodes -subj "/C=FR/ST=France/L=Paris/O=xython/OU=tests/CN=xython"

sudo sed -i 's,^#,,' /etc/xython/xython.cfg
sudo chgrp xython /etc/xython/xython*
sudo chmod 640 /etc/xython/xython.key
ls -l /etc/xython

cat /etc/xython/xython.cfg
/usr/bin/xython-tlsd --quit 5

sudo /etc/init.d/xython-tlsd start || exit $?

xythond -x 2 --debug --etcdir /etc/xython/ -D --wwwdir /var/lib/xython/www
echo $?
