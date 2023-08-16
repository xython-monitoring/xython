FROM debian:bookworm

RUN apt-get update
RUN apt-get -y install unzip python3-tz python3-celery python3-requests adduser redis-server sudo python3-redis procps apache2 rabbitmq-server

#RUN find |grep rabbitmq

RUN echo '%sudo ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

COPY xython-bookworm_deb.zip /
RUN unzip /xython-bookworm_deb.zip
RUN dpkg -i /xython_0*_amd64.deb

RUN usermod -aG sudo xython

COPY start.sh /
RUN chmod 755 /start.sh

USER xython

ENTRYPOINT ["/start.sh"]
