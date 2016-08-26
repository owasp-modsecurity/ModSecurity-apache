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

#Considerations, Concerns and Confusions
1-> For headers extraction there are too many options; but we can get those on both input filter and output filter as part of request_rec struct (headers_in and headers_out), I found several functions but no one is looking appropriate to me for libModSec as required by analyzing existing modules.

2-> For process connection there are also too many possibilities; IP address vs host address (client and server) which is also confusing that at which point what thing is needed, IP address or Host address or need to process both with two times use of process connection function.

3-> For configuration, I am also puzzled that what is appropriate or , I think connector should work on whole server that whatever come in and go out needs to process with libModSec.

#Contribute
Anyone from the community is most welcomed to contribute to this project especially in testing and debugging.

#Support
Please report issues, bugs, give feedback, suggestions and request new features at: tahirramzan1@gmail.com 

#Disclaimer
This is an unstable and feature incomplete version of ModSecurity v3 Apache Connector. This project is under development and it is NOT ready to be placed in production yet.
