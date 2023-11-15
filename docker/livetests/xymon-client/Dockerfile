FROM debian:bookworm

RUN apt-get update && apt-get -y install xymon-client
RUN sed -i 's,XYMONSERVERS=.*,XYMONSERVERS=xythond,' /etc/default/xymon-client

COPY start.sh /
RUN chmod 755 /start.sh
ENTRYPOINT ["/start.sh"]
