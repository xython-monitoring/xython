FROM debian:bookworm

RUN apt-get update
RUN apt-cache search tomcat
RUN apt-get -y install procps vsftpd cups dovecot-imapd dovecot-pop3d postfix slapd tomcat10 iproute2
COPY server.xml /etc/tomcat10/

COPY start.sh /
RUN chmod 755 /start.sh

ENTRYPOINT ["/start.sh"]
