#!/usr/bin/perl
# Tests net-reserve's daemon side: the DB-native DHCP plan (schema v24) —
# dhcp_ranges + dhcp_reservations DB methods, the OBSERVE kind=dhcp_range /
# dhcp_reservation(_delete) handlers, their authorization, and snapshot.
# Run with a writable netmgr DB via ~/.my.cnf (skips otherwise).
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::Config;
use NetMgr::DB;
use NetMgr::Manager;

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

my $cfg = NetMgr::Config->load('/no/such');
my $db  = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                          db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
$db->connect; $db->bootstrap_schema;

my $CIDR = '198.51.100.0/24';     # TEST-NET-2, won't collide with real data
sub cleanup {
    my $dbh = $db->dbh;
    $dbh->do("DELETE FROM dhcp_reservations WHERE subnet_cidr = ?", undef, $CIDR);
    $dbh->do("DELETE FROM dhcp_ranges       WHERE subnet_cidr = ?", undef, $CIDR);
}
cleanup();

# ---- 1. DB methods directly -----------------------------------------
my $r = $db->upsert_dhcp_range(subnet_cidr => $CIDR,
    start_ip => '198.51.100.100', end_ip => '198.51.100.200', zone => 'tst');
is($r->{op}, 'insert', 'range insert op');
is($r->{now}{end_ip}, '198.51.100.200', 'range end stored');
$r = $db->upsert_dhcp_range(subnet_cidr => $CIDR,
    start_ip => '198.51.100.100', end_ip => '198.51.100.150');
is($r->{op}, 'update', 'range re-upsert is update');
is(scalar(@{ $db->get_dhcp_ranges($CIDR) }), 1, 'one range for subnet');

my $rr = $db->upsert_dhcp_reservation(ip => '198.51.100.10',
    mac => 'AA:BB:CC:DD:EE:01', name => 'cam', subnet_cidr => $CIDR,
    grp => 'cameras', updated_by => 'unit');
is($rr->{op}, 'insert', 'reservation insert op');
is($rr->{now}{mac}, 'aa:bb:cc:dd:ee:01', 'mac lowercased on store');
is($rr->{now}{grp}, 'cameras', 'group stored');
is($db->get_dhcp_reservation('198.51.100.10')->{name}, 'cam', 'reservation fetch');

# ---- 2. Manager OBSERVE handlers + auth -----------------------------
my $mgr = NetMgr::Manager->new(config => $cfg, db => $db, log_fh => undef);

sub mkclient {
    my ($ident, $key) = @_;
    open(my $fh, '<', '/dev/null') or die "open /dev/null: $!";
    return { sock => $fh, ident => $ident, peer => 'unit', buffer => '',
             kind => 'producer', subs => {},
             ($key ? (auth => { key_id => $key, verified => 1 })
                   : (auth => undef)) };
}
my $agent = mkclient('agent', 'agent@unit');     # verified identity
my $anon  = mkclient('anon');                    # no identity, non-loopback
$mgr->{clients}{ fileno($_->{sock}) } = $_ for ($agent, $anon);

my %sent;
{ no warnings 'redefine';
  *NetMgr::Manager::_send = sub { push @{ $sent{$_[1]{ident}} }, $_[2] }; }
sub feed { $sent{$_[0]{ident}} = []; $mgr->_handle_line(@_); }
sub last_reply { (grep { /^(OK|ERR)\b/ } @{ $sent{$_[0]{ident}} || [] })[-1] // '' }

# unauthorized writer is rejected
feed($anon, "OBSERVE kind=dhcp_reservation ip=198.51.100.20 mac=aa:bb:cc:dd:ee:02");
like(last_reply($anon), qr/^ERR.*not authorized/, 'anon cannot reserve');
ok(!$db->get_dhcp_reservation('198.51.100.20'), 'no row written for anon');

# authorized writer succeeds
feed($agent, "OBSERVE kind=dhcp_reservation ip=198.51.100.20 "
           . "mac=aa:bb:cc:dd:ee:02 name=tower grp=servers");
like(last_reply($agent), qr/^OK/, 'agent reserve ok');
is($db->get_dhcp_reservation('198.51.100.20')->{name}, 'tower', 'agent reservation stored');
is($db->get_dhcp_reservation('198.51.100.20')->{updated_by}, 'agent@unit',
   'updated_by stamped from identity');
is($db->get_dhcp_reservation('198.51.100.20')->{subnet_cidr}, $CIDR,
   'subnet auto-derived from ip');

# bad input rejected
feed($agent, "OBSERVE kind=dhcp_reservation ip=not.an.ip mac=aa:bb:cc:dd:ee:03");
like(last_reply($agent), qr/^ERR.*bad ip/, 'bad ip rejected');

# range via OBSERVE
feed($agent, "OBSERVE kind=dhcp_range subnet_cidr=$CIDR "
           . "start_ip=198.51.100.60 end_ip=198.51.100.80 zone=z2");
like(last_reply($agent), qr/^OK/, 'agent add range ok');
is(scalar(@{ $db->get_dhcp_ranges($CIDR) }), 2, 'two ranges now');

# ---- 3. snapshot reflects the rows ----------------------------------
feed($agent, "SUBSCRIBE sub=9 mode=snapshot FROM dhcp_reservations");
my @rows = grep { /^ROW\b/ && /dhcp_reservations/ } @{ $sent{agent} };
ok((grep { /ip=198\.51\.100\.20\b/ } @rows), 'reservation appears in snapshot');

# ---- 3b. move / reallocate ------------------------------------------
feed($agent, "OBSERVE kind=dhcp_reservation_move ip=198.51.100.20 new_ip=198.51.100.25");
like(last_reply($agent), qr/^OK/, 'move ok');
ok(!$db->get_dhcp_reservation('198.51.100.20'), 'old IP freed after move');
is($db->get_dhcp_reservation('198.51.100.25')->{name}, 'tower', 'name carried to new IP');
is($db->get_dhcp_reservation('198.51.100.25')->{mac}, 'aa:bb:cc:dd:ee:02', 'mac carried');
is($db->get_dhcp_reservation('198.51.100.25')->{subnet_cidr}, $CIDR, 'subnet recomputed');
# moving a non-existent reservation errors
feed($agent, "OBSERVE kind=dhcp_reservation_move ip=198.51.100.99 new_ip=198.51.100.98");
like(last_reply($agent), qr/^ERR.*no reservation/, 'move of missing reservation errors');
# moving onto an occupied IP errors (reserve .10 still holds 'cam')
feed($agent, "OBSERVE kind=dhcp_reservation_move ip=198.51.100.25 new_ip=198.51.100.10");
like(last_reply($agent), qr/^ERR.*already reserved/, 'move onto occupied IP errors');
# normalise back to .20 for the delete section
feed($agent, "OBSERVE kind=dhcp_reservation_move ip=198.51.100.25 new_ip=198.51.100.20");
like(last_reply($agent), qr/^OK/, 'move back ok');

# ---- 3c. merge semantics (edit path) --------------------------------
# Seed a fully-populated row, then confirm:
#   - name-only edit (no mac, no grp, no notes)   preserves grp+notes+mac
#   - explicit empty string on a field            clears it
#   - create without an existing row STILL needs mac (guardrail)
feed($agent, "OBSERVE kind=dhcp_reservation ip=198.51.100.30 "
           . "mac=aa:bb:cc:dd:ee:30 name=orig grp=lab notes=chassis-A");
like(last_reply($agent), qr/^OK/, 'seed row for merge tests');
is($db->get_dhcp_reservation('198.51.100.30')->{grp},   'lab',       'grp seeded');
is($db->get_dhcp_reservation('198.51.100.30')->{notes}, 'chassis-A', 'notes seeded');

# (a) rename via omitted-mac edit: name changes, everything else survives
feed($agent, "OBSERVE kind=dhcp_reservation ip=198.51.100.30 name=renamed");
like(last_reply($agent), qr/^OK/, 'rename edit ok (no mac)');
my $r30 = $db->get_dhcp_reservation('198.51.100.30');
is($r30->{name},  'renamed',           'name updated');
is($r30->{mac},   'aa:bb:cc:dd:ee:30', 'mac preserved on omit');
is($r30->{grp},   'lab',               'grp preserved on omit');
is($r30->{notes}, 'chassis-A',         'notes preserved on omit');

# (b) explicit empty string clears the field; siblings still preserved
feed($agent, "OBSERVE kind=dhcp_reservation ip=198.51.100.30 grp=");
like(last_reply($agent), qr/^OK/, 'clear grp with empty string ok');
$r30 = $db->get_dhcp_reservation('198.51.100.30');
ok(!defined $r30->{grp} || $r30->{grp} eq '', 'grp cleared');
is($r30->{name},  'renamed',   'name preserved on clear');
is($r30->{notes}, 'chassis-A', 'notes preserved on clear');

# (c) create path still requires mac — no row at this ip yet
feed($agent, "OBSERVE kind=dhcp_reservation ip=198.51.100.31 name=nomac");
like(last_reply($agent), qr/^ERR.*mac required/, 'create without mac rejected');
ok(!$db->get_dhcp_reservation('198.51.100.31'), 'no row created without mac');

# clean the merge-test row so the delete section is unaffected
$db->delete_dhcp_reservation('198.51.100.30');

# ---- 4. delete ------------------------------------------------------
feed($agent, "OBSERVE kind=dhcp_reservation_delete ip=198.51.100.20");
like(last_reply($agent), qr/^OK/, 'delete ok');
ok(!$db->get_dhcp_reservation('198.51.100.20'), 'reservation gone after delete');

feed($agent, "OBSERVE kind=dhcp_range_delete subnet_cidr=$CIDR start_ip=198.51.100.60");
like(last_reply($agent), qr/^OK/, 'range delete ok');
is(scalar(@{ $db->get_dhcp_ranges($CIDR) }), 1, 'one range after delete');

cleanup();
done_testing();
