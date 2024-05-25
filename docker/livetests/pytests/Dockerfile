FROM debian:bookworm AS xython_deb_build

RUN apt-get update
RUN apt-get -y install python3-tz python3-celery python3-requests python3-redis git dh-cmake dh-python devscripts python3-setuptools dh-apache2 python3-dev python3-rrdtool python3-pysnmp4 python3-paramiko

ADD . /root/xython
RUN cd /root/xython/ && debuild -i -us -uc -b

FROM debian:bookworm

COPY --from=xython_deb_build /root/xython*deb /root/
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3-tz python3-celery python3-requests adduser redis-server sudo python3-redis procps apache2 rabbitmq-server netcat-openbsd iputils-ping python3-rrdtool python3-pysnmp4 wget python3-pytest python3-paramiko python-is-python3 curl python3-coverage

RUN dpkg -i /root/xython_0*_amd64.deb
RUN dpkg -i /root/xython-client_0*_amd64.deb

RUN useradd -m xtest
COPY docker/livetests/pytests/start.sh /home/xtest/
RUN chmod 755 /home/xtest/start.sh
USER xtest
WORKDIR /home/xtest
ADD --chown=xtest tests /home/xtest/tests
ADD --chown=xtest cgi /home/xtest/cgi
ADD --chown=xtest xython /home/xtest/xython



ENTRYPOINT ["/home/xtest/start.sh"]
