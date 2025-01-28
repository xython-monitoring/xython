FROM debian:bookworm

RUN apt-get update
RUN apt-get -y install squid

RUN sed -i 's,http_access deny all,#http_access deny all,' /etc/squid/squid.conf
RUN sed -i 's,#http_access allow localnet,http_access allow localnet,' /etc/squid/squid.conf

CMD ["/usr/sbin/squid", "--foreground"]
