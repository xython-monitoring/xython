#!/bin/sh

/etc/init.d/postfix start
/etc/init.d/dovecot start
/etc/init.d/slapd start

#cat /etc/tomcat10/server.xml
#cat /etc/systemd/system/multi-user.target.wants/tomcat10.service
export CATALINA_HOME=/usr/share/tomcat10
export CATALINA_BASE=/var/lib/tomcat10
export CATALINA_TMPDIR=/tmp
export JAVA_OPTS=-Djava.awt.headless=true
/usr/libexec/tomcat10/tomcat-start.sh&

sleep 5

ss -tlpn

sleep 365d
