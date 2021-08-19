
use strict;
use Apache::Test;
use Apache::TestRequest;

require "t/find_string_in_file.pl";

plan tests => 5, have_lwp;

my $audit_log = Apache::Test::config()->{vars}->{t_logs} . "/audit_logs.txt";

###############################################################################
# Test phases
# phase 1 (request headers)
###############################################################################
{
    # Remember position in audit log file before our test
    my $audit_log_start_size = -s $audit_log or die "Failed to access file: " . $audit_log;

    my $url = "/00-phases/00-phases_01.html";
    my $ct_header_name = "Content-Type";
    my $ct_header_val = "application/x-www-form-urlencoded";
    my $content = "arg1=val1&arg2=val2";
    my $res1 = POST $url, $ct_header_name => $ct_header_val, content => $content;

    # Expected results
    my $status_code_expected = 200;
    my $audit_log_expected = 'Matched "Operator \`Rx\' with parameter \`\^POST\' against variable \`REQUEST_LINE';
    my $audit_log_missing = 'Matched [\s\S]*(ARGS|RESPONSE)';

    my $audit_found_expected = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_expected);
    my $audit_found_missing = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_missing);

    ok (($res1->code == $status_code_expected) && ($audit_found_expected) && (not $audit_found_missing));
}

###############################################################################
# Test phases
# phase 2 (request body)
###############################################################################
{
    # Remember position in audit log file before our test
    my $audit_log_start_size = -s $audit_log or die "Failed to access file: " . $audit_log;

    my $url = "/00-phases/00-phases_02.html";
    my $ct_header_name = "Content-Type";
    my $ct_header_val = "application/x-www-form-urlencoded";
    my $content = "arg1=val1&arg2=val2";
    my $res1 = POST $url, $ct_header_name => $ct_header_val, content => $content;

    # Expected results
    my $status_code_expected = 200;
    my $audit_log_expected = 'Matched "Operator \`Rx\' with parameter \`\^POST\' against variable \`REQUEST_LINE[\s\S]*Matched "Operator \`Rx\' with parameter \`val1\' against variable \`ARGS';
    my $audit_log_missing = 'Matched [\s\S]*RESPONSE';

    my $audit_found_expected = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_expected);
    my $audit_found_missing = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_missing);

    ok (($res1->code == $status_code_expected) && ($audit_found_expected) && (not $audit_found_missing));
}

###############################################################################
# Test phases
# phase 3 (response headers)
###############################################################################
{
    # Remember position in audit log file before our test
    my $audit_log_start_size = -s $audit_log or die "Failed to access file: " . $audit_log;

    my $url = "/00-phases/00-phases_03.html";
    my $ct_header_name = "Content-Type";
    my $ct_header_val = "application/x-www-form-urlencoded";
    my $content = "arg1=val1&arg2=val2";
    my $res1 = POST $url, $ct_header_name => $ct_header_val, content => $content;

    # Expected results
    my $status_code_expected = 200;
    my $audit_log_expected = 'Matched "Operator \`Rx\' with parameter \`\^POST\' against variable \`REQUEST_LINE[\s\S]*Matched "Operator \`Rx\' with parameter \`val1\' against variable \`ARGS[\s\S]*Matched "Operator \`Rx\' with parameter \`.\' against variable \`RESPONSE_HEADERS';
    my $audit_log_missing = 'Matched [\s\S]*RESPONSE_BODY';

    my $audit_found_expected = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_expected);
    my $audit_found_missing = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_missing);

    ok (($res1->code == $status_code_expected) && ($audit_found_expected) && (not $audit_found_missing));
}

###############################################################################
# Test phases
# phase 4 (response body)
###############################################################################
{
    # Remember position in audit log file before our test
    my $audit_log_start_size = -s $audit_log or die "Failed to access file: " . $audit_log;

    my $url = "/00-phases/00-phases_04.html";
    my $ct_header_name = "Content-Type";
    my $ct_header_val = "application/x-www-form-urlencoded";
    my $content = "arg1=val1&arg2=val2";
    my $res1 = POST $url, $ct_header_name => $ct_header_val, content => $content;

    # Expected results
    my $status_code_expected = 200;
    my $audit_log_expected = 'Matched "Operator \`Rx\' with parameter \`\^POST\' against variable \`REQUEST_LINE[\s\S]*Matched "Operator \`Rx\' with parameter \`val1\' against variable \`ARGS[\s\S]*Matched "Operator \`Rx\' with parameter \`.\' against variable \`RESPONSE_HEADERS[\s\S]*Matched "Operator \`Rx\' with parameter \`TEST\' against variable \`RESPONSE_BODY';

    my $audit_found_expected = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_expected);

    ok (($res1->code == $status_code_expected) && ($audit_found_expected));
}

###############################################################################
# Test phases
# phase 5 (logging)
###############################################################################
{
    # Remember position in audit log file before our test
    my $audit_log_start_size = -s $audit_log or die "Failed to access file: " . $audit_log;

    my $url = "/00-phases/00-phases_05.html";
    my $ct_header_name = "Content-Type";
    my $ct_header_val = "application/x-www-form-urlencoded";
    my $content = "arg1=val1&arg2=val2";
    my $res1 = POST $url, $ct_header_name => $ct_header_val, content => $content;

    # Expected results
    my $status_code_expected = 200;
    my $audit_log_expected = 'Matched "Operator \`Rx\' with parameter \`\^POST\' against variable \`REQUEST_LINE[\s\S]*Matched "Operator \`Rx\' with parameter \`val1\' against variable \`ARGS[\s\S]*Matched "Operator \`Rx\' with parameter \`.\' against variable \`RESPONSE_HEADERS[\s\S]*Matched "Operator \`Rx\' with parameter \`TEST\' against variable \`RESPONSE_BODY';

    my $audit_found_expected = find_string_in_file($audit_log, $audit_log_start_size, $audit_log_expected);

    ok (($res1->code == $status_code_expected) && ($audit_found_expected));
}

