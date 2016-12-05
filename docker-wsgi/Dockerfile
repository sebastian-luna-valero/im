# Dockerfile to create a container with the IM service
FROM httpd:2.4
MAINTAINER Miguel Caballer <micafer1@upv.es>
LABEL version="1.5.0"
LABEL description="Container image to run the IM service with REST API over an apache server. (http://www.grycap.upv.es/im)"
EXPOSE 80

# Install IM 
RUN apt-get update && apt-get install -y gcc python-dev python-pip python-mysqldb python-pysqlite2 openssh-client sshpass libssl-dev libffi-dev libapache2-mod-wsgi apache2
# Install CherryPy to enable HTTPS in REST API
RUN pip install setuptools --upgrade -I
RUN pip install CherryPy pyOpenSSL --upgrade -I
# Add unresolved LibCloud dependency
RUN pip install backports.ssl_match_hostname
RUN pip install IM
COPY ansible.cfg /etc/ansible/ansible.cfg

# Install Apache wsgi
RUN apt install -y libapache2-mod-wsgi

RUN echo "LoadModule wsgi_module /usr/lib/apache2/modules/mod_wsgi.so" >> /usr/local/apache2/conf/httpd.conf

RUN mkdir /usr/local/apache2/im
COPY im_wsgi.py /usr/local/apache2/im/im.wsgi
COPY im_wsgi.conf /usr/local/apache2/conf/extra/im_wsgi.conf 

RUN echo "Include conf/extra/im_wsgi.conf " >> /usr/local/apache2/conf/httpd.conf
RUN chown www-data /var/www/
RUN chown www-data /etc/im/
RUN mkdir /var/log/im && chown www-data /var/log/im
