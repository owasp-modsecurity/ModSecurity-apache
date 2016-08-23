#ModSecurity-Apache
This repository contains the [ModSecurity v3 Apache Connector.]
(http://tahirramzan.github.io/ModSecurity-apache/)

#Installation Guide
1. Build libModSecurity [Compilation recipes]
(https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes)

2. Run the following commands:

      `export LD_LIBRARY_PATH=/usr/local/modsecurity/lib`
      
      `sudo apxs -i -a -c -I /opt/ModSecurity/headers -L /opt/ModSecurity/src/.libs/ -lmodsecurity apache_http_modsecurity.c config.c`

#Apache Settings 
The security3.conf file has Apache Configuration and Directives with comments which need to be placed in /etc/apache2/mods-enabled folder. 

#TODO
[The TODO List]
(https://github.com/tahirramzan/ModSecurity-apache/blob/master/TODO.md)

#Contribute
Anyone from the community is most welcomed to contribute to this project especially in testing and debugging.

#Support
Please report issues, bugs, give feedback, suggestions and request new features at: tahirramzan1@gmail.com 

#Disclaimer
This is an unstable and feature incomplete version of ModSecurity v3 Apache Connector. This project is under development and it is NOT ready to be placed in production yet.
