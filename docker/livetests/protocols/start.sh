#!/bin/sh

/etc/init.d/postfix start || exit $?
/etc/init.d/dovecot start || exit $?
/etc/init.d/vsftpd start || exit $?
/etc/init.d/slapd start || exit $?

export CATALINA_HOME=/usr/share/tomcat10
export CATALINA_BASE=/var/lib/tomcat10
export CATALINA_TMPDIR=/tmp
export JAVA_OPTS=-Djava.awt.headless=true
/usr/libexec/tomcat10/tomcat-start.sh&

sleep 5

ss -tlpn

tail -F /var/log/apache2/*log

sleep 365d
