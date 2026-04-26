#!/usr/bin/perl
# Tests Manager's SUBSCRIBE/UNSUB flow + emit-on-change.
# Run as root.
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
$db->connect; $db->bootstrap_schema;

sub cleanup {
    my $dbh = $db->dbh;
    $dbh->do("DELETE FROM events       WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM associations WHERE ap_mac LIKE ? OR client_mac LIKE ?",
             undef, "$TEST_PFX%", "$TEST_PFX%");
    $dbh->do("DELETE FROM dhcp_leases  WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM addresses    WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM ports        WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM aps          WHERE mac LIKE ?", undef, "$TEST_PFX%");
    $dbh->do("DELETE FROM interfaces   WHERE mac LIKE ?", undef, "$TEST_PFX%");
}
cleanup();

my $mgr = NetMgr::Manager->new(config => $cfg, db => $db,
                               log_fh => undef);    # discard

# Two fake clients: one producer, one consumer.
# Register them in $mgr->{clients} so _emit_change finds the consumer.
my $producer = { sock => undef, ident => 'p', kind => 'producer',
                 peer => 'unit', buffer => '', subs => {} };
my $consumer = { sock => undef, ident => 'c', kind => 'consumer',
                 peer => 'unit', buffer => '', subs => {} };
$mgr->{clients}{1001} = $producer;
$mgr->{clients}{1002} = $consumer;

# Capture sends per client
my %sent;   # ident => [lines]
{ no warnings 'redefine';
  *NetMgr::Manager::_send = sub {
      my ($self, $cli, $line) = @_;
      push @{ $sent{$cli->{ident}} }, $line;
  };
}

sub feed {
    my ($cli, $line) = @_;
    $sent{$cli->{ident}} = [];
    $mgr->_handle_line($cli, $line);
}

sub consumer_lines { @{ $sent{c} || [] } }

# Seed some interfaces via producer
feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:01 ip=203.0.113.10));
feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:02 ip=203.0.113.20));
feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:03 ip=192.168.99.30));

# --- Snapshot SUBSCRIBE ------------------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=1 mode=snapshot FROM interfaces");
    my @lines = consumer_lines();
    my @rows  = grep { /^ROW / } @lines;
    my @ours  = grep { /\Q$TEST_PFX\E/i } @rows;
    is(scalar @ours, 3, 'snapshot returned 3 test interfaces');
    ok((grep { /^EOS sub=1/ } @lines), 'EOS sent');
    ok((grep { /^OK sub=1/  } @lines), 'OK ack');
    is($consumer->{subs}{1}, undef, 'snapshot-only does not register stream');
}

# --- Snapshot+WHERE filter --------------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=2 mode=snapshot FROM addresses WHERE addr LIKE '203.0.113.%'");
    my @rows = grep { /^ROW / } consumer_lines();
    is(scalar @rows, 2, 'WHERE filter narrowed to 2 rows');
    ok(!(grep { /192\.168/ } @rows), '192.168 excluded');
}

# --- Stream subscribe --------------------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=3 mode=stream FROM interfaces");
    is(scalar(grep { /^ROW / } consumer_lines()), 0, 'stream gives no snapshot');
    ok((grep { /^OK sub=3/ } consumer_lines()), 'OK ack');
    ok($consumer->{subs}{3}, 'stream sub registered');

    # Now make a change that should push
    feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:04 ip=203.0.113.40));
    my @pushes = grep { /^ROW sub=3 / } consumer_lines();
    ok(scalar @pushes >= 1, 'got push for new iface');
    ok((grep { /\Q${TEST_PFX}00:04\E/i } @pushes), 'push has the new mac');
}

# --- Snapshot+stream --------------------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=4 mode=snapshot+stream FROM addresses WHERE addr LIKE '203.0.113.%'");
    my @snap = grep { /^ROW sub=4 / } consumer_lines();
    ok(scalar @snap >= 3, 'snapshot delivered');
    ok((grep { /^EOS sub=4/ } consumer_lines()), 'EOS for snapshot phase');
    ok($consumer->{subs}{4}, 'sub stays registered for stream');

    feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:05 ip=203.0.113.50));
    ok((grep { /^ROW sub=4 .*${TEST_PFX}00:05/i } consumer_lines()),
       'address change pushed');
}

# --- WHERE excludes the change ----------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=5 mode=stream FROM addresses WHERE addr = '999.999.999.999'");
    feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:06 ip=203.0.113.60));
    ok(!(grep { /^ROW sub=5 / } consumer_lines()),
       'no push when WHERE rejects');
}

# --- Events stream ----------------------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=6 mode=stream FROM events WHERE type = 'interface_new'");
    feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:07 ip=203.0.113.70));
    my @ev = grep { /^ROW sub=6 / } consumer_lines();
    ok(scalar @ev >= 1, 'event push received');
    ok((grep { /type=interface_new/ } @ev), 'event row has type');
}

# --- UNSUB ------------------------------------------------------------
{
    feed($consumer, "UNSUB sub=3");
    ok(!$consumer->{subs}{3}, 'sub removed');
    feed($producer, qq(OBSERVE kind=arp mac=${TEST_PFX}00:08 ip=203.0.113.80));
    ok(!(grep { /^ROW sub=3 / } consumer_lines()), 'no more pushes after UNSUB');
}

# --- Bad subscribe input ----------------------------------------------
{
    feed($consumer, "SUBSCRIBE sub=9 mode=stream FROM not_a_table");
    ok((grep { /^ERR.*unknown table/ } consumer_lines()), 'bad table rejected');

    feed($consumer, "SUBSCRIBE sub=10 mode=stream FROM interfaces WHERE )))");
    ok((grep { /^ERR.*WHERE/ } consumer_lines()), 'bad WHERE rejected');
}

cleanup();
$db->disconnect;
done_testing;
