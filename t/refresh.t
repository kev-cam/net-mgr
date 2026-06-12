#!/usr/bin/perl
# Tests NetMgr::Relay::refresh_subnet — the scoped one-shot pull behind
# net-mgr-relay's loopback REFRESH proxy. Spawns a real daemon (the
# "master") on the netmgr DB, seeds rows in two subnets, then refreshes
# ONE subnet into a scratch DB and asserts scope, FK handling, and
# replicated_from stamping. Skips without ~/.my.cnf or when the creds
# can't create the scratch DB.
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
use NetMgr::Relay;
use NetMgr::Protocol qw(parse_line);

my $PFX     = 'fe:ed:f5:';            # test MACs (cleanup key)
my $IN      = '192.0.2';              # TEST-NET-1: the subnet we refresh
my $OUT     = '203.0.113';            # TEST-NET-3: must NOT be pulled
my $SCRATCH = 'netmgr_refresh_t';     # destination ("local") DB

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

# ---- _subnet_like_prefix unit checks ---------------------------------
is(NetMgr::Relay::_subnet_like_prefix('192.0.2.0/24'),  '192.0.2.%',  '/24 prefix');
is(NetMgr::Relay::_subnet_like_prefix('192.0.2.128/25'),'192.0.2.%',  '/25 rounds to /24');
is(NetMgr::Relay::_subnet_like_prefix('10.20.0.0/16'),  '10.20.%',    '/16 prefix');
is(NetMgr::Relay::_subnet_like_prefix('10.0.0.0/8'),    '10.%',       '/8 prefix');
is(NetMgr::Relay::_subnet_like_prefix('10.0.0.0/4'),    undef,        'wider than /8 rejected');
is(NetMgr::Relay::_subnet_like_prefix('junk'),          undef,        'junk rejected');

# ---- REFRESH parses as a kv verb -------------------------------------
{
    my $cmd = parse_line("REFRESH subnet=192.0.2.0/24");
    is($cmd->{verb}, 'REFRESH', 'REFRESH verb parses');
    is($cmd->{kv}{subnet}, '192.0.2.0/24', 'subnet kv carried');
}

# ---- source DB: seed two subnets -------------------------------------
my $src = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                          db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
$src->connect; $src->bootstrap_schema;

# Scratch destination DB (create-or-skip: the [net-mgr] account may not
# have CREATE privilege; that's an environment limit, not a failure).
my $can_scratch = eval {
    $src->dbh->do("CREATE DATABASE IF NOT EXISTS $SCRATCH"); 1 };
plan skip_all => "creds can't create scratch DB $SCRATCH" unless $can_scratch;

sub cleanup_src {
    my $dbh = $src->dbh;
    $dbh->do("DELETE FROM dhcp_leases       WHERE mac LIKE ?", undef, "$PFX%");
    $dbh->do("DELETE FROM addresses         WHERE mac LIKE ?", undef, "$PFX%");
    $dbh->do("DELETE FROM interfaces        WHERE mac LIKE ?", undef, "$PFX%");
    $dbh->do("DELETE FROM dhcp_reservations WHERE subnet_cidr IN (?, ?)",
             undef, "$IN.0/24", "$OUT.0/24");
    $dbh->do("DELETE FROM dhcp_ranges       WHERE subnet_cidr IN (?, ?)",
             undef, "$IN.0/24", "$OUT.0/24");
}
cleanup_src();

for my $seed ([ "$IN.10",  '01' ], [ "$IN.11", '02' ], [ "$OUT.10", '03' ]) {
    my ($ip, $suff) = @$seed;
    $src->upsert_interface(mac => "$PFX$suff:01");
    $src->upsert_address(mac => "$PFX$suff:01", family => 'v4',
                         addr => $ip, source => 'unit:nmap');
}
$src->upsert_lease(mac => "${PFX}01:01", ip => "$IN.10", hostname => 'cam-t');
$src->upsert_dhcp_reservation(ip => "$IN.20", mac => "${PFX}aa:01",
    name => 'tower-t', subnet_cidr => "$IN.0/24", grp => 'servers');
$src->upsert_dhcp_reservation(ip => "$OUT.20", mac => "${PFX}aa:02",
    name => 'other-t', subnet_cidr => "$OUT.0/24");
$src->upsert_dhcp_range(subnet_cidr => "$IN.0/24",
    start_ip => "$IN.100", end_ip => "$IN.200", zone => 'tzone');
$src->upsert_dhcp_range(subnet_cidr => "$OUT.0/24",
    start_ip => "$OUT.100", end_ip => "$OUT.200");

# ---- spawn the "master" daemon ---------------------------------------
my $port_sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1',
                                      LocalPort => 0, Proto => 'tcp', Listen => 1);
my $port = $port_sock->sockport;
$port_sock->close;
my $listen = "127.0.0.1:$port";
diag("master daemon on $listen");

my $child = fork();
die "fork: $!" unless defined $child;
if ($child == 0) {
    my $cfg = NetMgr::Config->load('/no/such');
    $cfg->{manager}{listen} = $listen;
    my $db = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                             db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
    $db->connect; $db->bootstrap_schema;
    my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => undef);
    $mgr->run;
    exit 0;
}
END {
    if (defined $child && $child > 0) { kill 'TERM', $child; waitpid($child, 0) }
    if ($src && $src->dbh) {
        cleanup_src();
        eval { $src->dbh->do("DROP DATABASE $SCRATCH") };
    }
}
for (1..50) {
    my $probe = eval { NetMgr::Client->new(listen => $listen) };
    if ($probe) { eval { $probe->bye }; last }
    usleep(100_000);
}

# ---- destination DB ---------------------------------------------------
my $dst = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                          db => $SCRATCH, schema_dir => "$FindBin::Bin/../sql");
$dst->connect; $dst->bootstrap_schema;

# ---- the refresh -------------------------------------------------------
my $rows = NetMgr::Relay::refresh_subnet(
    db => $dst, peer => $listen, subnet => "$IN.0/24",
    replicated_from => 'tmaster');
cmp_ok($rows, '>=', 5, "refresh applied rows ($rows)");

my $dbh = $dst->dbh;
my ($n);

# in-scope rows landed
($n) = $dbh->selectrow_array(
    "SELECT COUNT(*) FROM addresses WHERE addr LIKE '$IN.%'");
is($n, 2, 'both in-subnet addresses pulled');
($n) = $dbh->selectrow_array(
    "SELECT COUNT(*) FROM interfaces WHERE mac LIKE ?", undef, "$PFX%");
cmp_ok($n, '>=', 2, 'FK interface rows auto-created');
($n) = $dbh->selectrow_array(
    "SELECT COUNT(*) FROM dhcp_leases WHERE ip = '$IN.10'");
is($n, 1, 'in-subnet lease pulled');
my $resv = $dbh->selectrow_hashref(
    "SELECT * FROM dhcp_reservations WHERE ip = '$IN.20'");
ok($resv, 'in-subnet reservation pulled');
is($resv->{name}, 'tower-t',  'reservation name carried');
is($resv->{grp},  'servers',  'reservation group carried');
my $range = $dbh->selectrow_hashref(
    "SELECT * FROM dhcp_ranges WHERE subnet_cidr = '$IN.0/24'");
ok($range, 'in-subnet dynamic range pulled');
is($range->{zone}, 'tzone', 'range zone carried');

# replicated_from stamped
my ($rf) = $dbh->selectrow_array(
    "SELECT replicated_from FROM addresses WHERE addr = '$IN.10'");
is($rf, 'tmaster', 'replicated_from stamped on pulled address');

# out-of-scope rows did NOT land
($n) = $dbh->selectrow_array(
    "SELECT COUNT(*) FROM addresses WHERE addr LIKE '$OUT.%'");
is($n, 0, 'out-of-subnet addresses NOT pulled');
($n) = $dbh->selectrow_array(
    "SELECT COUNT(*) FROM dhcp_reservations WHERE ip LIKE '$OUT.%'");
is($n, 0, 'out-of-subnet reservations NOT pulled');
($n) = $dbh->selectrow_array(
    "SELECT COUNT(*) FROM dhcp_ranges WHERE subnet_cidr = '$OUT.0/24'");
is($n, 0, 'out-of-subnet ranges NOT pulled');

# idempotent: a second refresh applies the same rows without error
my $rows2 = NetMgr::Relay::refresh_subnet(
    db => $dst, peer => $listen, subnet => "$IN.0/24",
    replicated_from => 'tmaster');
is($rows2, $rows, 'second refresh idempotent');

done_testing();
