FROM ubuntu:22.04

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -qy install python3-tz python3-celery python3-requests adduser redis-server sudo python3-redis procps apache2 rabbitmq-server wget iputils-ping netcat-openbsd

RUN echo '%sudo ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

COPY xython*deb /
RUN dpkg -i /xython_0*_amd64.deb
RUN dpkg -i /xython-client_0*_amd64.deb

RUN usermod -aG sudo xython

COPY start.sh /
RUN chmod 755 /start.sh

RUN chown -R xython /etc/xython

USER xython

ENTRYPOINT ["/start.sh"]
