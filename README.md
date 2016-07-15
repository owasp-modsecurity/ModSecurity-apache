# ModSecurity-apache
ModSecurity v3 Apache Connector

export LD_LIBRARY_PATH=/usr/local/modsecurity/lib

sudo apxs -i -a -c -I /opt/ModSecurity/headers -L /opt/ModSecurity/src/.libs/ -lmodsecurity apache_http_modsecurity.c
