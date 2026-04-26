#!/usr/bin/perl
# End-to-end TCP test. Spawns the daemon as a forked child on a random
# localhost port; runs a real client (NetMgr::Client) through HELLO,
# OBSERVE, SUBSCRIBE snapshot, and verifies rows landed in MySQL.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use IO::Socket::INET;
use POSIX qw(:sys_wait_h);
use Time::HiRes qw(usleep);
use NetMgr::Config;
use NetMgr::DB;
use NetMgr::Manager;
use NetMgr::Client;
use NetMgr::Protocol qw(parse_line);

my $TEST_PFX = 'fe:ed:fa:ce:';

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

# Pick a free port
my $port_sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                       Proto => 'tcp', Listen => 1);
my $port = $port_sock->sockport;
$port_sock->close;
my $listen = "127.0.0.1:$port";
diag("daemon will listen on $listen");

# Cleanup helper
sub cleanup {
    my $db = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                             db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
    $db->connect;
    my $dbh = $db->dbh;
    $dbh->do("DELETE FROM events       WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM addresses    WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM aps          WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM interfaces   WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $db->disconnect;
}
cleanup();

# Spawn the daemon as a child
my $child = fork();
die "fork: $!" unless defined $child;
if ($child == 0) {
    # build a minimal config in memory by forging environment
    my $cfg = NetMgr::Config->load('/no/such');
    $cfg->{manager}{listen} = $listen;
    my $db = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                             db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
    $db->connect; $db->bootstrap_schema;
    my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => undef);
    $mgr->run;
    exit 0;
}

# Wait for daemon to bind (poll connect)
my $cli;
for (1..50) {
    $cli = eval { NetMgr::Client->new(listen => $listen) };
    last if $cli;
    usleep(100_000);
}
ok($cli, 'daemon accepted TCP connection');

END {
    if (defined $child && $child > 0) {
        kill 'TERM', $child;
        waitpid($child, 0);
    }
    cleanup();
}

# HELLO + OBSERVE
ok($cli->hello(source => 'tcp-test', pid => $$), 'HELLO ok');

my $reply = $cli->observe(kind => 'arp',
                          mac => "${TEST_PFX}TC:01",
                          ip  => '203.0.113.111');
like($reply, qr/^OK\b/, 'OBSERVE arp ok');

$reply = $cli->observe(kind => 'ap_self',
                       mac  => "${TEST_PFX}TC:AP",
                       ip   => '203.0.113.112',
                       name => 'tcptest-ap',
                       ssid => 'test-ssid');
like($reply, qr/^OK\b/, 'OBSERVE ap_self ok');

# SUBSCRIBE snapshot — should return our two interfaces
my $rows = $cli->snapshot(7, 'interfaces');
my @ours = grep { lc($_->{mac}) =~ /^\Q$TEST_PFX\E/i } @$rows;
ok(scalar @ours >= 2, 'snapshot saw our interfaces (got ' . scalar(@ours) . ')');

# SUBSCRIBE with WHERE
my $aps = $cli->snapshot(8, 'aps', where => "ssid = 'test-ssid'");
is(scalar @$aps, 1, 'WHERE filter returns just the test ap');
is($aps->[0]{ssid}, 'test-ssid', 'ssid matches');

$cli->bye;

done_testing;
