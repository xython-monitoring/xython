FROM debian:bookworm

RUN apt-get update
RUN apt-get -y install procps openssh-server

RUN echo "Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com" >> /etc/ssh/sshd_config

# user with password
RUN useradd userpass -m
RUN echo "userpass:cipass" | chpasswd

# user with ssh key
RUN useradd userkey -m
RUN mkdir /run/sshd
RUN ssh-keygen -A
RUN mkdir /home/userpass/.ssh
COPY valid.pub /home/userpass/.ssh/authorized_keys
RUN chown -R userpass /home/userpass
#COPY start.sh /
#RUN chmod 755 /start.sh
CMD ["/usr/sbin/sshd", "-D", "-e"]
#ENTRYPOINT ["/start.sh"]
