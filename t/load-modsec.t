
use strict;
use Apache::Test;
use Apache::TestRequest;
use FileHandle;

plan tests => 1;


my $body = GET_BODY "/test.html";
ok($body, qr/test/);


