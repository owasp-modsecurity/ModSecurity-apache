
use strict;
use Apache::Test;
use Apache::TestRequest;
use FileHandle;

plan tests => 1, need_module 'security3_module.c';

my $body = GET_BODY "/test.html";
ok($body, qr/test/);


