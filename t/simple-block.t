
use strict;
use Apache::Test;
use Apache::TestRequest;
use FileHandle;
use Data::Dumper;
  
plan tests => 11;

my $res = GET "/index.html?evil=evil";
ok $res->code == 200;

my $res1 = GET "/block-evil-1/evil?evil=evil";
ok $res1->code == 403;
my $res2 = GET "/block-evil-2/evil?evil=evil";
ok $res2->code == 403;
my $res3 = GET "/block-evil-3/evil?evil=evil";
ok $res3->code == 403;
my $res4 = GET "/block-evil-4/evil?evil=evil";
ok $res4->code == 403;

# Too late to block.
my $res5 = GET "/block-evil-5/evil?evil=evil";
ok $res5->code == 200;


my $res1l = GET "/block-evil-1-loc/evil?evil=evil";
ok $res1l->code == 402;
my $res2l = GET "/block-evil-2-loc/evil?evil=evil";
ok $res2l->code == 402;
my $res3l = GET "/block-evil-3-loc/evil?evil=evil";
ok $res3l->code == 402;
my $res4l = GET "/block-evil-4-loc/evil?evil=evil";
ok $res4l->code == 402;

# Too late to block.
my $res5l = GET "/block-evil-5-loc/evil?evil=evil";
ok $res5l->code == 200;


