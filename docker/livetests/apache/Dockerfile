FROM debian:bookworm

RUN apt-get update
RUN apt-get -y install procps apache2

COPY cont.html /var/www/html
RUN touch /var/www/html/forbiden
RUN chmod 600 /var/www/html/forbiden

RUN mkdir /var/www/html/private
COPY htaccess /var/www/html/private/.htaccess
RUN htpasswd -bc /var/www/passwd test testpass
RUN echo "THIS IS PRIVATE" > /var/www/html/private/index.html
RUN chgrp -R www-data /var/www

#RUN grep -ri override /etc/apache2
RUN sed -i 's,AllowOverride None,AllowOverride All,' /etc/apache2/apache2.conf

COPY start.sh /
RUN chmod 755 /start.sh

ENTRYPOINT ["/start.sh"]
