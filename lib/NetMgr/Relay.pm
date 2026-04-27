package NetMgr::Relay;
# Subscribes to a peer net-mgr instance and replicates rows into the
# local DB. One process per peer (forked by sbin/net-mgr-relay).
#
# Replicated tables, in dependency order:
#   machines      → matched by primary_name; populates a peer_id→local_id
#                    map used by downstream tables
#   hostnames     → machine_id translated via map
#   interfaces    → machine_id translated; mac is the natural key
#   addresses     → mac is the natural key
#   ports         → mac+port+proto natural key
#   aps           → mac PK
#   associations  → ap_mac+client_mac natural keys
#   dhcp_leases   → mac+ip natural keys
#   aliases       → name PK; machine_id translated
#
# Loop prevention: applies via direct DB upsert, NOT via the manager's
# emit_change pipeline. So a replicated row doesn't get re-streamed back
# to peers — bidirectional peering is safe.

use strict;
use warnings;
use Carp qw(croak);
use NetMgr::Client;
use NetMgr::Protocol qw(parse_line);

my @REPLICATED = qw(
    machines hostnames interfaces addresses ports
    aps associations dhcp_leases aliases
);

sub run {
    my (%args) = @_;
    my $peer = $args{peer} or croak "peer required";
    my $db   = $args{db}   or croak "db required";
    my $log  = $args{log_fh} // \*STDERR;
    my $backoff = $args{backoff} // 5;

    while (1) {
        my $err;
        eval {
            _log($log, "[relay] connecting to $peer");
            my $cli = NetMgr::Client->new(listen => $peer, timeout => 5);
            $cli->hello(consumer => "net-mgr-relay.$$");
            _run_session($cli, $db, $log);
            $cli->bye;
        };
        $err = $@;
        chomp $err if defined $err;
        _log($log, "[relay] $peer disconnected: $err") if $err;
        sleep $backoff;
    }
}

sub _run_session {
    my ($cli, $db, $log) = @_;
    my %idmap;     # peer_machine_id → local_machine_id

    my $sub = 0;
    my %sub_table;
    for my $t (@REPLICATED) {
        $sub++;
        $sub_table{$sub} = $t;
        $cli->send_line("SUBSCRIBE sub=$sub mode=snapshot+stream FROM $t");
    }

    while (defined(my $line = $cli->recv_line)) {
        my $cmd = parse_line($line);
        next unless $cmd;
        if ($cmd->{verb} eq 'ROW') {
            my $kv     = $cmd->{kv};
            my $table  = $kv->{table};
            my $apply  = __PACKAGE__->can("_apply_$table") or next;
            eval { $apply->($db, $kv, \%idmap) };
            _log($log, "[relay] apply $table: $@") if $@;
        } elsif ($cmd->{verb} eq 'ERR') {
            _log($log, "[relay] peer ERR: $cmd->{msg}");
        }
        # ignore OK / EOS
    }
}

sub _log {
    my ($fh, $msg) = @_;
    my @t = localtime;
    printf {$fh} "%04d-%02d-%02d %02d:%02d:%02d %s\n",
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0], $msg;
}

# ---- per-table apply functions --------------------------------------

sub _apply_machines {
    my ($db, $row, $idmap) = @_;
    my $name = $row->{primary_name};
    return unless defined $name && length $name;
    my ($lid) = $db->dbh->selectrow_array(
        "SELECT id FROM machines WHERE primary_name = ?", undef, $name);
    if ($lid) {
        $db->upsert_machine(id => $lid,
            primary_name => $name,
            online => $row->{online} // 0,
            notes  => $row->{notes});
    } else {
        my $r = $db->upsert_machine(
            primary_name => $name,
            online => $row->{online} // 0,
            notes  => $row->{notes});
        $lid = $r->{now}{id};
    }
    $idmap->{ $row->{id} } = $lid if $row->{id};
}

sub _apply_hostnames {
    my ($db, $row, $idmap) = @_;
    my $mid = $idmap->{ $row->{machine_id} // '' };
    return unless $mid && $row->{name} && $row->{source};
    $db->upsert_hostname(
        machine_id => $mid,
        name       => $row->{name},
        source     => $row->{source},
    );
}

sub _apply_interfaces {
    my ($db, $row, $idmap) = @_;
    return unless $row->{mac};
    my %args = ( mac => $row->{mac} );
    $args{kind}    = $row->{kind}    if defined $row->{kind};
    $args{vendor}  = $row->{vendor}  if defined $row->{vendor};
    $args{online}  = $row->{online}  if defined $row->{online};
    # Preserve peer's last_observed exactly (don't auto-bump on receiver)
    $args{last_observed} = $row->{last_observed}
        if defined $row->{last_observed} && length $row->{last_observed};
    if (defined $row->{machine_id} && $row->{machine_id} ne '') {
        my $lmid = $idmap->{ $row->{machine_id} };
        $args{machine_id} = $lmid if $lmid;
    }
    $db->upsert_interface(%args);
}

sub _apply_addresses {
    my ($db, $row, $idmap) = @_;
    return unless $row->{mac} && $row->{addr} && $row->{family};
    $db->upsert_address(
        mac    => $row->{mac},
        family => $row->{family},
        addr   => $row->{addr},
        (defined $row->{source} ? (source => $row->{source}) : ()),
        (defined $row->{last_observed} && length $row->{last_observed}
            ? (last_observed => $row->{last_observed}) : ()),
    );
}

sub _apply_ports {
    my ($db, $row, $idmap) = @_;
    return unless $row->{mac} && defined $row->{port};
    $db->upsert_port(
        mac     => $row->{mac},
        port    => $row->{port},
        proto   => $row->{proto} // 'tcp',
        service => $row->{service},
    );
}

sub _apply_aps {
    my ($db, $row, $idmap) = @_;
    return unless $row->{mac};
    $db->upsert_ap(
        mac   => $row->{mac},
        ssid  => $row->{ssid},
        model => $row->{model},
        board => $row->{board},
    );
}

sub _apply_associations {
    my ($db, $row, $idmap) = @_;
    return unless $row->{ap_mac} && $row->{client_mac};
    $db->upsert_association(
        ap_mac     => $row->{ap_mac},
        client_mac => $row->{client_mac},
        iface      => $row->{iface},
        signal     => $row->{signal},
    );
}

sub _apply_dhcp_leases {
    my ($db, $row, $idmap) = @_;
    return unless $row->{mac} && $row->{ip};
    $db->upsert_lease(
        mac      => $row->{mac},
        ip       => $row->{ip},
        hostname => $row->{hostname},
        expires  => $row->{expires},
        ap_mac   => $row->{ap_mac},
    );
}

sub _apply_aliases {
    my ($db, $row, $idmap) = @_;
    return unless $row->{name};
    my $mid = $idmap->{ $row->{machine_id} // '' };
    return unless $mid;
    $db->upsert_alias(
        name               => $row->{name},
        machine_id         => $mid,
        prefer_subnet_cidr => $row->{prefer_subnet_cidr},
        source             => $row->{source},
        notes              => $row->{notes},
    );
}

1;
