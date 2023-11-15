FROM debian:bookworm AS xython_deb_build

RUN apt-get update
RUN apt-get -y install python3-tz python3-celery python3-requests python3-redis python3-coverage git dh-cmake dh-python devscripts python3-setuptools dh-apache2 python3-dev python3-rrdtool python3-pysnmp4

RUN cd /root && git clone https://github.com/xython-monitoring/xython && cd xython && git checkout html
RUN cd /root/xython/ && debuild -i -us -uc -b


FROM debian:bookworm

COPY --from=xython_deb_build /root/xython*deb /root/
RUN apt-get update
RUN apt-get -y install python3-tz python3-celery python3-requests adduser redis-server sudo python3-redis procps apache2 rabbitmq-server netcat-openbsd iputils-ping python3-rrdtool python3-pysnmp4 wget python3-pytest

RUN dpkg -i /root/xython_0*_amd64.deb
RUN dpkg -i /root/xython-client_0*_amd64.deb

RUN echo '%sudo ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
RUN usermod -aG sudo xython

RUN echo "0.0.0.0 snmpd snmp:disk:memory" >> /etc/xython/hosts.cfg
RUN echo "0.0.0.0 xymon-client # conn" >> /etc/xython/hosts.cfg
RUN echo "0.0.0.0 protocols # conn ftp smtp imap ldap" >> /etc/xython/hosts.cfg
RUN echo "0.0.0.0 apache # conn http://apache/ cont;http://apache/cont.html;TEST httpstatus;http://apache/forbiden;403" >> /etc/xython/hosts.cfg

# uncomment hack to have output
#COPY x.sh /
#RUN chmod 755 /x.sh
#RUN sed -i 's,start-stop-daemon --start.*,start-stop-daemon --start --quiet --oknodo --umask 007 --pidfile $PIDFILE --chuid xython:xython --background --exec /x.sh,' /etc/init.d/xythond

RUN mkdir /tests
COPY tests/livetest.py /tests/

RUN sed -i 's,self.GENPAGE_INTERVAL = 30,self.GENPAGE_INTERVAL = 10,' /usr/lib/python3/dist-packages/xython/xython.py

COPY start.sh /
RUN chmod 755 /start.sh

ENTRYPOINT ["/start.sh"]
