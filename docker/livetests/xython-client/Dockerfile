FROM debian:bookworm AS xython_deb_build

RUN apt-get update
RUN apt-get -y install python3-tz python3-celery python3-requests python3-redis python3-coverage git dh-cmake dh-python devscripts python3-setuptools dh-apache2 python3-dev python3-rrdtool python3-pysnmp4 python3-paramiko

ADD . /root/xython
RUN cd /root/xython/ && debuild -i -us -uc -b


FROM debian:bookworm

COPY --from=xython_deb_build /root/xython*deb /root/
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install adduser procps netcat-openbsd iputils-ping wget curl openssl

RUN dpkg -i /root/xython-client_0*_amd64.deb

RUN sed -i 's,#XYTHON_SRV=127.0.0.1,XYTHON_SRV=xython-server,' /etc/xython/xython-client.cfg

COPY docker/livetests/xython-client/start.sh /
RUN chmod 755 /start.sh

ENTRYPOINT ["/start.sh"]
