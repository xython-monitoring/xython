#!/bin/sh

sudo mkdir -p /run/xython-client/ || exit $?
sudo chown $(id -u -n) /run/xython-client/ || exit $?

sudo mkdir -p /etc/xython
sudo cp etc/xython-client.cfg /etc/xython/
sudo chmod -R o+rX /etc/xython/

pwd
export PATH=./client/:$PATH

nc -l -p 1984 > /tmp/result &
ss -tlpn
sh client/xython-client.sh -d

sleep 2

ls -l /tmp/
ls -l /run/xython-client/
cat /run/xython-client/xython.err
md5sum /run/xython-client/xython.msg
md5sum /tmp/result


echo '======================='
nc -l -p 1985 > /tmp/result &
sh client/xython-client.sh -d --tlsmode openssl
cat /run/xython-client/xython.err
md5sum /run/xython-client/xython.msg
md5sum /tmp/result

echo '======================='
sudo sed -i 's,#XYTHON_SRV=127.0.0.1,XYTHON_SRV=127.0.0.1:1984,' /etc/xython/xython-client.cfg
nc -l -p 1984 > /tmp/result &
sh client/xython-client.sh -d --tlsmode curl
cat /run/xython-client/xython.err
md5sum /run/xython-client/xython.msg
md5sum /tmp/result

