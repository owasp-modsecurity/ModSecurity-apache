
use strict;
use Apache::Test;
use Apache::TestRequest;
use FileHandle;

plan tests => 1;


my $res = GET "/block-evil/?evil=evil";
print " This is the test return code: " . $res->code . "\n";
ok $res->code == 403;


