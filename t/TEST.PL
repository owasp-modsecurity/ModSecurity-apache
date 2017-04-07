#!/usr/bin/perl

use strict;
use warnings FATAL => 'all';

use Apache::TestRun;
Apache::TestRun->new->run(@ARGV);
