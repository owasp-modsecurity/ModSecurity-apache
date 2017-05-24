
use strict;
use Apache::Test;
use Apache::TestRequest;
use FileHandle;

plan tests => 1;
#plan tests => 1, need_module 'src/apache_http_modsecurity.c';


my $body = GET_BODY "/test.html";
ok($body, qr/test/);


