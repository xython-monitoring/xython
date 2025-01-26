FROM debian:bookworm
ARG PACKAGES

RUN apt-get update
RUN apt-get -y install procps openssh-server sudo $PACKAGES

# add extra port
RUN echo "Port 22" >> /etc/ssh/sshd_config
RUN echo "Port 222" >> /etc/ssh/sshd_config

RUN sed -i 's,UsePAM,#UsePAM,' /etc/ssh/sshd_config

# user with password
RUN useradd userpass -m
RUN echo "userpass:cipass" | chpasswd

# user with ssh key
RUN useradd userkey -m
RUN usermod -p '*' userkey

# user with ssh key and sudo rigths
RUN useradd xadmin -m
RUN usermod -p '*' xadmin
RUN echo "%xadmin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN mkdir /run/sshd
RUN ssh-keygen -A

RUN mkdir /home/userkey/.ssh
COPY valid.pub /home/userkey/.ssh/authorized_keys
RUN chown -R userkey /home/userkey

RUN mkdir /home/xadmin/.ssh
COPY valid.pub /home/xadmin/.ssh/authorized_keys
RUN chown -R xadmin /home/xadmin

CMD ["/usr/sbin/sshd", "-D", "-e"]
