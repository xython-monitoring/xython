FROM debian:bookworm
ARG PACKAGES

RUN apt-get update
RUN apt-get -y install procps openssh-server $PACKAGES

# add extra port
RUN echo "Port 22" >> /etc/ssh/sshd_config
RUN echo "Port 222" >> /etc/ssh/sshd_config

RUN sed -i 's,UsePAM,#UsePAM,' /etc/ssh/sshd_config

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

CMD ["/usr/sbin/sshd", "-D", "-e"]
