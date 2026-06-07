#!/usr/bin/perl
# NetMgr::Client::split_hostport / join_hostport — endpoint parsing that
# tolerates IPv6 literals (bracketed for a port, bare otherwise) as well as
# the historical host:port and bare-host forms. No socket/DB needed.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::Client;

# split_hostport: input -> [expected_host, expected_port]
my @split_cases = (
    ['127.0.0.1:7531'   => ['127.0.0.1', '7531']],
    ['192.168.15.9:7531'=> ['192.168.15.9', '7531']],
    ['nas3:7531'        => ['nas3', '7531']],
    ['nas3'             => ['nas3', undef]],
    ['127.0.0.1'        => ['127.0.0.1', undef]],
    ['[fd00::1]:7531'   => ['fd00::1', '7531']],
    ['[fd00:nm:1::1]:7531' => ['fd00:nm:1::1', '7531']],
    ['[::1]:7531'       => ['::1', '7531']],
    ['[fd00::1]'        => ['fd00::1', undef]],
    ['fd00::1'          => ['fd00::1', undef]],   # bare v6, no port
    ['::1'              => ['::1', undef]],
    [''                 => [undef, undef]],
);

for my $c (@split_cases) {
    my ($in, $want) = @$c;
    my ($h, $p) = NetMgr::Client::split_hostport($in);
    is($h, $want->[0], "split host of '$in'");
    is($p, $want->[1], "split port of '$in'");
}

# join_hostport: [host, port] -> expected string
my @join_cases = (
    [['127.0.0.1', 7531] => '127.0.0.1:7531'],
    [['nas3', 7531]      => 'nas3:7531'],
    [['nas3', undef]     => 'nas3'],
    [['fd00::1', 7531]   => '[fd00::1]:7531'],   # v6 gets bracketed
    [['fd00:nm:1::1', 7531] => '[fd00:nm:1::1]:7531'],
    [['::1', undef]      => '[::1]'],
    [['fd00::1', '']     => '[fd00::1]'],         # empty port == no port
);

for my $c (@join_cases) {
    my ($args, $want) = @$c;
    is(NetMgr::Client::join_hostport(@$args), $want,
       "join (@{[ map { defined ? $_ : 'undef' } @$args ]})");
}

# Round-trip: split then join restores the canonical bracketed form.
for my $addr ('127.0.0.1:7531', 'nas3:7531', '[fd00::1]:7531', '[::1]:7531') {
    my ($h, $p) = NetMgr::Client::split_hostport($addr);
    is(NetMgr::Client::join_hostport($h, $p), $addr, "round-trip '$addr'");
}

done_testing;
