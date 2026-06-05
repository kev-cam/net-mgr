#!/usr/bin/perl
# Regression: Manager::_send must serialize wide chars to UTF-8 bytes before
# syswrite. A non-ASCII chat body (e.g. an em-dash, U+2014) previously warned
# "Wide character in syswrite" and desynced the byte/char length+offset math,
# aborting the daemon. No DB needed — drives _send over a socketpair.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use Socket;
use NetMgr::Manager;

socketpair(my $rd, my $wr, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
    or plan skip_all => "socketpair: $!";

my $mgr  = bless {}, 'NetMgr::Manager';      # _send only touches $cli->{sock}
my $cli  = { sock => $wr };
my $line = "MSG body=\x{2014}dash";          # em-dash = wide char
ok(utf8::is_utf8($line), 'test line carries a wide char');

my @warns;
my $ok = do {
    local $SIG{__WARN__} = sub { push @warns, $_[0] };
    eval { $mgr->_send($cli, $line); 1 };
};
ok($ok, '_send with a wide char does not die') or diag($@);
is(scalar(grep { /Wide character/ } @warns), 0,
   "no 'Wide character' warning from _send");

my $got = '';
sysread($rd, $got, 256);
is($got, "MSG body=\xe2\x80\x94dash\n",
   '_send emitted UTF-8 bytes (U+2014 -> E2 80 94)');
ok(!utf8::is_utf8($got), 'received data is a byte string');

done_testing();
