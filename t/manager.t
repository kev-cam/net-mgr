#!/usr/bin/perl
# Tests Manager's OBSERVE dispatch by feeding it parsed commands directly.
# Run as root (needs DB access).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::Config;
use NetMgr::DB;
use NetMgr::Manager;
use NetMgr::Protocol qw(parse_line);

my $TEST_PFX = 'fe:ed:fa:ce:';

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

my $cfg = NetMgr::Config->load('/no/such');
my $db  = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                          db => 'netmgr',
                          schema_dir => "$FindBin::Bin/../sql");
$db->connect;
$db->bootstrap_schema;

sub cleanup {
    my $dbh = $db->dbh;
    $dbh->do("DELETE FROM events       WHERE mac LIKE ? OR addr = ?",
             undef, "$TEST_PFX%", '203.0.113.42');
    $dbh->do("DELETE FROM associations WHERE ap_mac LIKE ? OR client_mac LIKE ?",
             undef, "$TEST_PFX%", "$TEST_PFX%");
    $dbh->do("DELETE FROM dhcp_leases  WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM addresses    WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM ports        WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM aps          WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM interfaces   WHERE mac LIKE ?", undef, "$TEST_PFX%");
}
cleanup();

# Capture log
my $log_buf = '';
open my $log_fh, '>', \$log_buf;
my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => $log_fh);

# Capture sent replies via a fake client object
my $cli = { sock => undef, ident => 'test', kind => 'producer', peer => 'unit', buffer => '' };

# Override _send to capture last reply
my @sent;
{ no warnings 'redefine';
  *NetMgr::Manager::_send = sub { my (undef, undef, $line) = @_; push @sent, $line };
}

sub feed {
    my ($line) = @_;
    @sent = ();
    my $cmd = parse_line($line);
    return unless $cmd;
    $mgr->_handle_line($cli, $line);
    return $sent[-1];
}

# --- ap_self -----------------------------------------------------------
{
    my $reply = feed(qq(OBSERVE kind=ap_self mac=${TEST_PFX}AP:01 ip=203.0.113.42 name=testap board="Test Board" ssid=net1,net2));
    is($reply, 'OK', 'ap_self OK');
    my $iface = $db->get_interface_by_mac("${TEST_PFX}AP:01");
    is($iface->{kind}, 'wifi', 'ap iface kind=wifi');
    is($iface->{online}, 1, 'ap iface online');
    my $ap = $db->dbh->selectrow_hashref(
        "SELECT * FROM aps WHERE mac = ?", undef, "${TEST_PFX}ap:01");
    is($ap->{ssid}, 'net1,net2', 'ap ssid recorded');
    my $addr = $db->dbh->selectrow_hashref(
        "SELECT * FROM addresses WHERE mac = ? AND addr = ?",
        undef, "${TEST_PFX}ap:01", '203.0.113.42');
    ok($addr, 'ap addr recorded');
    my @evs = @{ $db->dbh->selectall_arrayref(
        "SELECT type FROM events WHERE mac = ? ORDER BY id",
        { Slice => {} }, "${TEST_PFX}ap:01") };
    my @types = map { $_->{type} } @evs;
    ok((grep /^interface_new$/, @types), "got interface_new event (got: @types)");
    ok((grep /^interface_online$/, @types), 'got interface_online event');
    ok((grep /^address_added$/, @types), 'got address_added event');
}

# --- arp ---------------------------------------------------------------
{
    feed(qq(OBSERVE kind=arp mac=${TEST_PFX}CL:01 ip=203.0.113.50));
    my $iface = $db->get_interface_by_mac("${TEST_PFX}CL:01");
    is($iface->{kind}, 'ethernet');
    is($iface->{online}, 1);

    # second ARP for same mac shouldn't generate duplicate interface_new
    my $before = $db->dbh->selectrow_array(
        "SELECT COUNT(*) FROM events WHERE mac = ? AND type = 'interface_new'",
        undef, "${TEST_PFX}cl:01");
    feed(qq(OBSERVE kind=arp mac=${TEST_PFX}CL:01 ip=203.0.113.50));
    my $after = $db->dbh->selectrow_array(
        "SELECT COUNT(*) FROM events WHERE mac = ? AND type = 'interface_new'",
        undef, "${TEST_PFX}cl:01");
    is($after, $before, 'no duplicate interface_new on repeat arp');
}

# --- association -------------------------------------------------------
{
    # Need an AP for the ap_ip→ap_mac lookup
    feed(qq(OBSERVE kind=ap_self mac=${TEST_PFX}AP:02 ip=203.0.113.43 name=testap2));
    feed(qq(OBSERVE kind=association ap_ip=203.0.113.43 client_mac=${TEST_PFX}CL:02 iface=eth1));
    my $row = $db->dbh->selectrow_hashref(
        "SELECT * FROM associations WHERE ap_mac=? AND client_mac=?",
        undef, "${TEST_PFX}ap:02", "${TEST_PFX}cl:02");
    ok($row, 'association recorded');
    is($row->{iface}, 'eth1');
}

# --- lease (epoch coercion) -------------------------------------------
{
    my $exp = time() + 1800;
    feed(qq(OBSERVE kind=lease mac=${TEST_PFX}CL:03 ip=203.0.113.60 hostname=leaseclient expires=$exp));
    my $row = $db->dbh->selectrow_hashref(
        "SELECT * FROM dhcp_leases WHERE mac = ?",
        undef, "${TEST_PFX}cl:03");
    is($row->{hostname}, 'leaseclient');
    like($row->{expires}, qr/^\d{4}-/);
}

# --- port -------------------------------------------------------------
{
    feed(qq(OBSERVE kind=port mac=${TEST_PFX}CL:01 port=22 service="OpenSSH 8.9"));
    my $row = $db->dbh->selectrow_hashref(
        "SELECT * FROM ports WHERE mac=? AND port=22",
        undef, "${TEST_PFX}cl:01");
    is($row->{service}, 'OpenSSH 8.9');
    my $ev = $db->dbh->selectrow_hashref(
        "SELECT * FROM events WHERE mac=? AND type='port_opened'",
        undef, "${TEST_PFX}cl:01");
    ok($ev, 'port_opened event');
}

# --- GONE ------------------------------------------------------------
{
    feed(qq(GONE mac=${TEST_PFX}CL:01));
    my $iface = $db->get_interface_by_mac("${TEST_PFX}CL:01");
    is($iface->{online}, 0, 'iface marked offline by GONE');
    my $ev = $db->dbh->selectrow_hashref(
        "SELECT * FROM events WHERE mac=? AND type='interface_offline'",
        undef, "${TEST_PFX}cl:01");
    ok($ev, 'interface_offline event');
}

# --- bad input -------------------------------------------------------
{
    my $reply = feed("OBSERVE kind=arp ip=203.0.113.99");   # missing mac
    like($reply, qr/^ERR/, 'missing mac → ERR');

    $reply = feed("OBSERVE kind=mystery mac=${TEST_PFX}XX:01");
    like($reply, qr/^ERR/, 'unknown kind → ERR');
}

cleanup();
$db->disconnect;
done_testing;
