#!/usr/bin/perl
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Test::More;
use File::Temp qw(tempfile);
use NetMgr::Config;

# defaults when file is missing
{
    my $cfg = NetMgr::Config->load('/no/such/path');
    is($cfg->{manager}{listen}, '127.0.0.1:7531', 'default listen');
    is($cfg->{mysql}{db},       'netmgr',         'default db');
    is($cfg->{scanner}{presence_interval}, 90,    'default presence interval');
    is($cfg->{timeouts}{ap},    120,              'default AP timeout');
    is($cfg->{timeouts}{dhcp},  'lease',          'default dhcp = lease');
    is_deeply($cfg->{bindings}{machines}, {},     'no bindings');
}

# parse a real config
{
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh <<'EOF';
# net-mgr config
[manager]
listen = 127.0.0.1:9999
log    = /tmp/net-mgr.log

[mysql]
db = my-netmgr

[scanner]
networks          = 192.168.15.0/24, 192.168.17.0/24
presence_interval = 30s
discover_interval = 12h
reprobe_ports     = 1d

[timeouts]
ap    = 2m
fping = 90
nmap  = 1d
dhcp  = lease

[paths]
dnsmasq_conf_glob = /etc/dnsmasq/conf.d/*.conf
oui_csv           = /var/lib/ieee-data/oui.csv

[bindings]
machine "kestrel"   = aa:bb:cc:dd:ee:01, AA:BB:CC:DD:EE:02
machine "router-up" = 11:22:33:44:55:66
EOF
    close $fh;

    my $cfg = NetMgr::Config->load($path);
    is($cfg->{manager}{listen},          '127.0.0.1:9999');
    is($cfg->{mysql}{db},                'my-netmgr');
    is($cfg->{scanner}{networks},        '192.168.15.0/24, 192.168.17.0/24');
    is($cfg->{scanner}{presence_interval}, 30,    '30s parsed');
    is($cfg->{scanner}{discover_interval}, 43200, '12h parsed');
    is($cfg->{scanner}{reprobe_ports},      86400,'1d parsed');
    is($cfg->{timeouts}{ap},               120,   '2m parsed');
    is($cfg->{timeouts}{fping},            90,    'bare 90 parsed');
    is($cfg->{timeouts}{dhcp},             'lease','lease passed through');
    is($cfg->{paths}{dnsmasq_conf_glob},   '/etc/dnsmasq/conf.d/*.conf');

    is_deeply($cfg->{bindings}{machines}{'kestrel'},
              ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02'],
              'bindings: macs lowercased');
    is_deeply($cfg->{bindings}{machines}{'router-up'},
              ['11:22:33:44:55:66']);
}

# malformed
{
    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh "loose_key = 1\n";
    close $fh;
    eval { NetMgr::Config->load($path) };
    ok($@, 'line outside section throws');
}

# parse_duration unit cases
{
    is(NetMgr::Config::parse_duration('60s'),  60);
    is(NetMgr::Config::parse_duration('5m'),   300);
    is(NetMgr::Config::parse_duration('1h'),   3600);
    is(NetMgr::Config::parse_duration('7d'),   604800);
    is(NetMgr::Config::parse_duration('2w'),   1209600);
    is(NetMgr::Config::parse_duration('42'),   42, 'bare int = seconds');
    is(NetMgr::Config::parse_duration('lease'),'lease', 'symbolic pass-through');
}

done_testing;
