#!/usr/bin/perl
# Run as root (needs read of /root/.my.cnf and full privs on `netmgr`):
#   sudo prove -Ilib t/db.t
#
# Uses the live `netmgr` database. All test rows use a sentinel MAC prefix
# of 'fe:ed:fa:ce:' so we can tear down at end-of-test without touching
# real data.

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::DB;

my $TEST_MAC_PREFIX = 'fe:ed:fa:ce:';

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

my $db = NetMgr::DB->new(
    defaults_file => $mycnf,
    section       => 'net-mgr',
    db            => 'netmgr',
    schema_dir    => "$FindBin::Bin/../sql",
);
$db->connect;
ok($db->dbh, 'connected');

# Bootstrap (idempotent)
my $v = $db->bootstrap_schema;
is($v, $NetMgr::DB::SCHEMA_VERSION, "schema bootstrapped to v$v");

# Cleanup any leftover from a previous failed run
sub cleanup {
    my $dbh = $db->dbh;
    $dbh->do("DELETE FROM events       WHERE mac LIKE ? OR addr = ?",
             undef, "$TEST_MAC_PREFIX%", '203.0.113.99');
    $dbh->do("DELETE FROM associations WHERE ap_mac LIKE ? OR client_mac LIKE ?",
             undef, "$TEST_MAC_PREFIX%", "$TEST_MAC_PREFIX%");
    $dbh->do("DELETE FROM dhcp_leases  WHERE mac LIKE ?", undef, "$TEST_MAC_PREFIX%");
    $dbh->do("DELETE FROM addresses    WHERE mac LIKE ?", undef, "$TEST_MAC_PREFIX%");
    $dbh->do("DELETE FROM ports        WHERE mac LIKE ?", undef, "$TEST_MAC_PREFIX%");
    $dbh->do("DELETE FROM aps          WHERE mac LIKE ?", undef, "$TEST_MAC_PREFIX%");
    $dbh->do("DELETE FROM hostnames    WHERE source = 'test-suite'");
    $dbh->do("DELETE FROM interfaces   WHERE mac LIKE ?", undef, "$TEST_MAC_PREFIX%");
    $dbh->do("DELETE FROM machines     WHERE primary_name LIKE 'test-suite-%'");
}
cleanup();

# --- interface insert/update -------------------------------------------
{
    my $r = $db->upsert_interface(mac => "${TEST_MAC_PREFIX}00:01",
                                  vendor => 'TestCo', kind => 'ethernet',
                                  online => 1);
    is($r->{op}, 'insert', 'iface insert');
    is($r->{now}{vendor}, 'TestCo');
    is($r->{now}{online}, 1);

    $r = $db->upsert_interface(mac => "${TEST_MAC_PREFIX}00:01");
    is($r->{op}, 'noop', 'iface noop on no fields');

    $r = $db->upsert_interface(mac => "${TEST_MAC_PREFIX}00:01",
                               vendor => 'TestCo');
    is($r->{op}, 'noop', 'iface noop when value unchanged');

    $r = $db->upsert_interface(mac => "${TEST_MAC_PREFIX}00:01",
                               online => 0);
    is($r->{op}, 'update', 'iface update online');
    is_deeply($r->{changed_fields}, ['online']);
    is($r->{was}{online}, 1);
    is($r->{now}{online}, 0);
}

# --- machine + hostname binding ----------------------------------------
{
    my $m = $db->upsert_machine(primary_name => 'test-suite-host1', online => 1);
    is($m->{op}, 'insert');
    my $mid = $m->{now}{id};
    ok($mid > 0, "got machine id $mid");

    # Bind the interface to this machine
    my $r = $db->upsert_interface(mac => "${TEST_MAC_PREFIX}00:01",
                                  machine_id => $mid);
    is($r->{op}, 'update', 'iface bound to machine');
    is($r->{now}{machine_id}, $mid);

    my $h = $db->upsert_hostname(machine_id => $mid,
                                 name => 'test-host.local',
                                 source => 'test-suite');
    is($h->{op}, 'insert');

    $h = $db->upsert_hostname(machine_id => $mid,
                              name => 'test-host.local',
                              source => 'test-suite');
    is($h->{op}, 'noop', 'hostname noop on dup');
}

# --- address (v4 + v6) -------------------------------------------------
{
    my $r = $db->upsert_address(mac => "${TEST_MAC_PREFIX}00:01",
                                family => 'v4', addr => '203.0.113.99');
    is($r->{op}, 'insert', 'v4 addr insert');
    $r = $db->upsert_address(mac => "${TEST_MAC_PREFIX}00:01",
                             family => 'v6', addr => 'fe80::feed:face:1');
    is($r->{op}, 'insert', 'v6 addr insert');
    $r = $db->upsert_address(mac => "${TEST_MAC_PREFIX}00:01",
                             family => 'v4', addr => '203.0.113.99');
    is($r->{op}, 'noop', 'addr noop on dup');
}

# --- ports -------------------------------------------------------------
{
    my $r = $db->upsert_port(mac => "${TEST_MAC_PREFIX}00:01",
                             port => 22, service => 'ssh');
    is($r->{op}, 'insert');
    $r = $db->upsert_port(mac => "${TEST_MAC_PREFIX}00:01",
                          port => 22, service => 'OpenSSH 8.9');
    is($r->{op}, 'update', 'service updated');
    is($r->{now}{service}, 'OpenSSH 8.9');
}

# --- AP + association --------------------------------------------------
{
    $db->upsert_interface(mac => "${TEST_MAC_PREFIX}AP:00", kind => 'ethernet');
    $db->upsert_interface(mac => "${TEST_MAC_PREFIX}CL:00", kind => 'wifi');

    my $a = $db->upsert_ap(mac => "${TEST_MAC_PREFIX}AP:00",
                           ssid => 'test-net', model => 'TestRouter');
    is($a->{op}, 'insert', 'ap insert');

    my $as = $db->upsert_association(ap_mac => "${TEST_MAC_PREFIX}AP:00",
                                     client_mac => "${TEST_MAC_PREFIX}CL:00",
                                     iface => 'eth1', signal => -54);
    is($as->{op}, 'insert', 'association insert');

    $as = $db->upsert_association(ap_mac => "${TEST_MAC_PREFIX}AP:00",
                                  client_mac => "${TEST_MAC_PREFIX}CL:00",
                                  signal => -50);
    is($as->{op}, 'update');
    is($as->{now}{signal}, -50);
}

# --- DHCP lease (epoch coercion) --------------------------------------
{
    my $r = $db->upsert_lease(mac => "${TEST_MAC_PREFIX}CL:00",
                              ip  => '203.0.113.99',
                              hostname => 'test-host',
                              expires  => time() + 3600);
    is($r->{op}, 'insert');
    like($r->{now}{expires}, qr/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/, 'epoch → DATETIME');

    $r = $db->upsert_lease(mac => "${TEST_MAC_PREFIX}CL:00",
                           ip  => '203.0.113.99',
                           hostname => 'test-host-renamed');
    is($r->{op}, 'update');
    is($r->{now}{hostname}, 'test-host-renamed');
}

# --- event log ---------------------------------------------------------
{
    my $id = $db->log_event(type => 'device_new',
                            mac  => "${TEST_MAC_PREFIX}00:01",
                            addr => '203.0.113.99');
    ok($id > 0, "logged event id=$id");
}

# --- query_table snapshot ---------------------------------------------
{
    my $rows = $db->query_table('interfaces');
    ok(scalar @$rows > 0, 'snapshot returns rows');
    my @ours = grep { $_->{mac} =~ /^\Q$TEST_MAC_PREFIX\E/i } @$rows;
    ok(scalar @ours >= 3, 'snapshot includes our test rows');
}

# Cleanup
cleanup();
$db->disconnect;
ok(!$db->dbh, 'disconnected');

done_testing;
