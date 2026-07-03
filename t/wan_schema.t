#!/usr/bin/perl
# t/wan_schema.t — commit A of the wan-failover series: verify the schema-v34
# migration.
#
# Uses a SCRATCH DB (netmgr_wan_schema_t) — creates it, boots NetMgr::DB
# against it, then asserts the three wan_* tables exist with the expected
# column shape and that schema_version now includes 34. Not a full round-trip
# test: commit A has no upsert helpers, so there is nothing to insert-and-read
# back yet.
#
# Skips when there is no [net-mgr] mycnf, or when the account can't create
# the scratch DB (mirrors t/refresh.t's environment guard).

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use NetMgr::DB;

my $SCRATCH = 'netmgr_wan_schema_t';

my $mycnf = (-r "$ENV{HOME}/.my.cnf") ? "$ENV{HOME}/.my.cnf"
          : (-r '/root/.my.cnf')      ? '/root/.my.cnf'
          : undef;
plan skip_all => "no readable .my.cnf with [net-mgr] section" unless $mycnf;

# Use a throwaway "server" DB just to run the CREATE DATABASE statement.
my $src = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                          db => 'netmgr', schema_dir => "$FindBin::Bin/../sql");
eval { $src->connect };
plan skip_all => "can't connect to netmgr (this is a bootstrap probe)" if $@;

my $can_scratch = eval {
    $src->dbh->do("DROP DATABASE IF EXISTS $SCRATCH");
    $src->dbh->do("CREATE DATABASE $SCRATCH");
    1;
};
plan skip_all => "creds can't create scratch DB $SCRATCH" unless $can_scratch;
END {
    if ($src && $src->dbh) {
        eval { $src->dbh->do("DROP DATABASE IF EXISTS $SCRATCH") };
    }
}

# Boot the schema on the fresh scratch DB — this exercises the schema.sql
# fresh-install path (loads the file wholesale) plus any post-file _apply_migration
# runs. Either way $SCHEMA_VERSION must be reached.
my $db = NetMgr::DB->new(defaults_file => $mycnf, section => 'net-mgr',
                         db => $SCRATCH, schema_dir => "$FindBin::Bin/../sql");
$db->connect;
my $v = $db->bootstrap_schema;
is($v, $NetMgr::DB::SCHEMA_VERSION, "schema bootstrapped to v$v");
cmp_ok($v, '>=', 34, 'schema at least v34');

# schema_version row for 34 is present.
my ($has34) = $db->dbh->selectrow_array(
    "SELECT COUNT(*) FROM schema_version WHERE version = 34");
is($has34, 1, 'schema_version has row for v34');

# All three tables exist.
for my $t (qw(wan_services wan_service_candidates wan_service_health)) {
    my ($n) = $db->dbh->selectrow_array(
        "SELECT COUNT(*) FROM information_schema.tables
          WHERE table_schema = DATABASE() AND table_name = ?", undef, $t);
    is($n, 1, "table $t exists");
}

# Column shape via SHOW CREATE TABLE — cheap, verifies both the fields and
# the PK layout without depending on information_schema quirks.
sub _create {
    my ($tbl) = @_;
    my $row = $db->dbh->selectrow_arrayref("SHOW CREATE TABLE $tbl");
    return $row ? $row->[1] : '';
}

my $ws_ddl = _create('wan_services');
like($ws_ddl, qr/PRIMARY KEY \(`name`\)/,           'wan_services PK is name');
like($ws_ddl, qr/`active_member`\s+varchar/i,       'wan_services.active_member');
like($ws_ddl, qr/`last_status`\s+varchar/i,         'wan_services.last_status');
like($ws_ddl, qr/`orchestrator_mode`\s+varchar/i,   'wan_services.orchestrator_mode');
like($ws_ddl, qr/`probe_targets`\s+varchar/i,       'wan_services.probe_targets');
like($ws_ddl, qr/`probe_interval_s`\s+int/i,        'wan_services.probe_interval_s');
like($ws_ddl, qr/`fail_streak_threshold`\s+int/i,   'wan_services.fail_streak_threshold');
like($ws_ddl, qr/`replicated_from`\s+varchar/i,     'wan_services.replicated_from');
like($ws_ddl, qr/KEY `idx_ws_replicated`/i,         'wan_services idx_ws_replicated');

my $wsc_ddl = _create('wan_service_candidates');
like($wsc_ddl, qr/PRIMARY KEY \(`service_name`,`member`\)/,
     'wan_service_candidates PK (service_name, member)');
like($wsc_ddl, qr/`priority`\s+int/i,               'wsc.priority');
like($wsc_ddl, qr/`iface`\s+varchar/i,              'wsc.iface');
like($wsc_ddl, qr/`mac`\s+char/i,                   'wsc.mac');
like($wsc_ddl, qr/`apply_hook`\s+varchar/i,         'wsc.apply_hook');
like($wsc_ddl, qr/`teardown_hook`\s+varchar/i,      'wsc.teardown_hook');
like($wsc_ddl, qr/`probe_when_standby`\s+tinyint/i, 'wsc.probe_when_standby');
like($wsc_ddl, qr/`replicated_from`\s+varchar/i,    'wsc.replicated_from');
like($wsc_ddl, qr/KEY `idx_wsc_svc_prio`/i,         'wsc idx_wsc_svc_prio');

my $wsh_ddl = _create('wan_service_health');
like($wsh_ddl, qr/PRIMARY KEY \(`service_name`,`member`,`target`\)/,
     'wan_service_health PK (service_name, member, target)');
like($wsh_ddl, qr/`last_check`\s+datetime/i,         'wsh.last_check');
like($wsh_ddl, qr/`last_ok`\s+datetime/i,            'wsh.last_ok');
like($wsh_ddl, qr/`last_status`\s+varchar/i,         'wsh.last_status');
like($wsh_ddl, qr/`last_rtt_ms`\s+float/i,           'wsh.last_rtt_ms');
like($wsh_ddl, qr/`consecutive_failures`\s+int/i,    'wsh.consecutive_failures');
like($wsh_ddl, qr/`replicated_from`\s+varchar/i,     'wsh.replicated_from');
like($wsh_ddl, qr/KEY `idx_wsh_svc`/i,               'wsh idx_wsh_svc');

# List helpers work on an empty DB (returns [] / 0), and count returns 0.
my $svcs = $db->list_wan_services;
is(ref $svcs,     'ARRAY', 'list_wan_services returns arrayref');
is(scalar @$svcs, 0,       'list_wan_services empty on fresh DB');

my $cands = $db->list_wan_service_candidates;
is(ref $cands,     'ARRAY', 'list_wan_service_candidates returns arrayref');
is(scalar @$cands, 0,       'list_wan_service_candidates empty');

my $health = $db->list_wan_service_health('somesvc');
is(ref $health,     'ARRAY', 'list_wan_service_health returns arrayref (scoped)');
is(scalar @$health, 0,       'list_wan_service_health empty');

is($db->count_wan_services, 0, 'count_wan_services is 0 on fresh DB');

$db->disconnect;
done_testing();
