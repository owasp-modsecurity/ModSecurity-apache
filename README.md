#ModSecurity-Apache

This repository contains the ModSecurity v3 Apache Connector.

#Installation Guide

1. Build libModSecurity [Compilation recipes]
(https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes)

2. Run the following commands:

`export LD_LIBRARY_PATH=/usr/local/modsecurity/lib`

`sudo apxs -i -a -c -I /opt/ModSecurity/headers -L /opt/ModSecurity/src/.libs/ -lmodsecurity apache_http_modsecurity.c`

#Disclaimer
This is an unstable and feature incomplete version of ModSecurity v3 Apache Connector. This project is under development and it is NOT ready to be placed in production yet.
