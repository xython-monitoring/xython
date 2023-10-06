FROM debian:bookworm

RUN apt-get update
RUN apt-get -y install snmpd
RUN sed -i 's,^agentaddress.*,agentaddress 0.0.0.0,' /etc/snmp/snmpd.conf
RUN sed -i 's,public,nopublic,' /etc/snmp/snmpd.conf
RUN sed -i 's,.1.3.*,.1,' /etc/snmp/snmpd.conf

COPY start.sh /
RUN chmod 755 /start.sh

ENTRYPOINT ["/start.sh"]
