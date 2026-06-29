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
    dhcp_ranges dhcp_reservations
    mesh_tunnels
);

sub run {
    my (%args) = @_;
    my $peer = $args{peer} or croak "peer required";
    my $db   = $args{db}   or croak "db required";
    my $log  = $args{log_fh} // \*STDERR;
    my $backoff = $args{backoff} // 5;
    # The cluster_member name to stamp on every replicated row's
    # replicated_from column. The script (net-mgr-relay) passes
    # this in from its election result. Without it, rows still
    # replicate but aren't tagged — useful for --peer debug runs
    # where we don't want to claim a particular master identity.
    my $repl_from = $args{replicated_from};

    while (1) {
        my $err;
        eval {
            _log($log, "[relay] connecting to $peer");
            my $cli = NetMgr::Client->new(listen => $peer, timeout => 5);
            $cli->hello(consumer => "net-mgr-relay.$$");
            # If no master_name was passed in, derive it from the
            # peer's own STATUS — saves the caller from doing it.
            $repl_from //= do {
                my $st = eval { $cli->status };
                $st && $st->{cluster_member};
            };
            _run_session($cli, $db, $log, $repl_from);
            $cli->bye;
        };
        $err = $@;
        chomp $err if defined $err;
        _log($log, "[relay] $peer disconnected: $err") if $err;
        sleep $backoff;
    }
}

sub _run_session {
    my ($cli, $db, $log, $repl_from) = @_;
    my %idmap;     # peer_machine_id → local_machine_id

    my $sub = 0;
    my %sub_table;
    for my $t (@REPLICATED) {
        $sub++;
        $sub_table{$sub} = $t;
        $cli->send_line("SUBSCRIBE sub=$sub mode=snapshot+stream FROM $t");
    }

    while (defined(my $line = $cli->recv_line)) {
        # Don't let one unparsable line tear down the whole subscription (which
        # then reconnects and re-streams from scratch). parse_line croaks on a
        # malformed line; log + skip it and keep replicating.
        my $cmd = eval { parse_line($line) };
        if ($@ || !$cmd) {
            _log($log, "[relay] skipping unparsable line: "
                     . substr($line // '', 0, 80)) if $@;
            next;
        }
        if ($cmd->{verb} eq 'ROW') {
            my $kv     = $cmd->{kv};
            my $table  = $kv->{table};
            if (($kv->{op} // '') eq 'delete') {
                # Propagate the master's deletions. Without this the relay
                # upserts a delete event's row straight back in, resurrecting it
                # — a pool the master removed never went away on followers.
                if (my $del = __PACKAGE__->can("_delete_$table")) {
                    eval { $del->($db, $kv) };
                    _log($log, "[relay] delete $table: $@") if $@;
                }
            } else {
                my $apply = __PACKAGE__->can("_apply_$table") or next;
                eval { $apply->($db, $kv, \%idmap, $repl_from) };
                _log($log, "[relay] apply $table: $@") if $@;
            }
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
#
# Each _apply_$table($db, $row, $idmap, $repl_from):
#   1. UPSERT the row using the existing DB method.
#   2. If $repl_from is set, stamp replicated_from on the row by
#      its natural key. This is a single UPDATE; cheap and lets
#      the upsert methods stay untouched. On the next replication
#      tick the master's value is re-stamped, so local divergence
#      between ticks gets overwritten.
#
# _stamp($db, $table, $repl_from, WHERE_clause, @binds) does the
# stamp uniformly so each apply function stays short.

sub _stamp {
    my ($db, $table, $repl_from, $where, @binds) = @_;
    return unless defined $repl_from && length $repl_from;
    $db->dbh->do(
        "UPDATE $table SET replicated_from = ? WHERE $where",
        undef, $repl_from, @binds
    );
}

sub _apply_machines {
    my ($db, $row, $idmap, $repl_from) = @_;
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
    _stamp($db, 'machines', $repl_from, 'id = ?', $lid);
}

sub _apply_hostnames {
    my ($db, $row, $idmap, $repl_from) = @_;
    my $mid = $idmap->{ $row->{machine_id} // '' };
    return unless $mid && $row->{name} && $row->{source};
    $db->upsert_hostname(
        machine_id => $mid,
        name       => $row->{name},
        source     => $row->{source},
    );
    _stamp($db, 'hostnames', $repl_from,
           'machine_id = ? AND name = ? AND source = ?',
           $mid, $row->{name}, $row->{source});
    # Authoritative-name semantic: a 'self' source replicates from the master
    # downstream when a daemon registered itself; it asserts THIS machine is
    # the one answering to $name. Drop any other-mid bindings for the same
    # name on this follower's local DB — that's how a clevo-lx restart's
    # dedup reaches gateway3/gateway2/zmc1 without per-leaf operator auth.
    # Other sources (dhcp, dhcp.master, etc.) don't trigger cleanup —
    # only producer-as-authority does.
    if (($row->{source} // '') eq 'self') {
        my $orphans = $db->dbh->selectall_arrayref(
            "SELECT DISTINCT machine_id FROM hostnames
              WHERE name = ? AND machine_id <> ?",
            { Slice => {} }, $row->{name}, $mid);
        for my $r (@{ $orphans || [] }) {
            $db->delete_hostname($r->{machine_id}, $row->{name});
        }
    }
}

sub _apply_interfaces {
    my ($db, $row, $idmap, $repl_from) = @_;
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
    _stamp($db, 'interfaces', $repl_from, 'mac = ?', lc $row->{mac});
}

sub _apply_addresses {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{mac} && $row->{addr} && $row->{family};
    $db->upsert_address(
        mac    => $row->{mac},
        family => $row->{family},
        addr   => $row->{addr},
        (defined $row->{source} ? (source => $row->{source}) : ()),
        (defined $row->{last_observed} && length $row->{last_observed}
            ? (last_observed => $row->{last_observed}) : ()),
    );
    _stamp($db, 'addresses', $repl_from,
           'mac = ? AND family = ? AND addr = ?',
           lc $row->{mac}, $row->{family}, $row->{addr});
}

sub _apply_ports {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{mac} && defined $row->{port};
    $db->upsert_port(
        mac     => $row->{mac},
        port    => $row->{port},
        proto   => $row->{proto} // 'tcp',
        service => $row->{service},
    );
    _stamp($db, 'ports', $repl_from,
           'mac = ? AND port = ? AND proto = ?',
           lc $row->{mac}, $row->{port}, $row->{proto} // 'tcp');
}

sub _apply_aps {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{mac};
    $db->upsert_ap(
        mac     => $row->{mac},
        ssid    => $row->{ssid},
        model   => $row->{model},
        board   => $row->{board},
        exclude => $row->{exclude},
    );
    _stamp($db, 'aps', $repl_from, 'mac = ?', lc $row->{mac});
}

sub _apply_associations {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{ap_mac} && $row->{client_mac};
    $db->upsert_association(
        ap_mac     => $row->{ap_mac},
        client_mac => $row->{client_mac},
        iface      => $row->{iface},
        signal     => $row->{signal},
    );
    _stamp($db, 'associations', $repl_from,
           'ap_mac = ? AND client_mac = ?',
           lc $row->{ap_mac}, lc $row->{client_mac});
}

sub _apply_dhcp_leases {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{mac} && $row->{ip};
    $db->upsert_lease(
        mac      => $row->{mac},
        ip       => $row->{ip},
        hostname => $row->{hostname},
        expires  => $row->{expires},
        ap_mac   => $row->{ap_mac},
    );
    _stamp($db, 'dhcp_leases', $repl_from,
           'mac = ? AND ip = ?', lc $row->{mac}, $row->{ip});
}

sub _apply_aliases {
    my ($db, $row, $idmap, $repl_from) = @_;
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
    _stamp($db, 'aliases', $repl_from, 'name = ?', $row->{name});
}

# DB-native DHCP plan. No machine-id remap — these are keyed by IP/subnet,
# not machine, so they replicate verbatim.
sub _apply_dhcp_ranges {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{subnet_cidr} && $row->{start_ip} && $row->{end_ip};
    $db->upsert_dhcp_range(
        subnet_cidr => $row->{subnet_cidr},
        start_ip    => $row->{start_ip},
        end_ip      => $row->{end_ip},
        zone        => $row->{zone},
        notes       => $row->{notes},
    );
    # An AP serves a single pool: once its current range is in, drop any OTHER
    # range still tagged to the same server (a stale replica the master changed
    # or moved but whose delete we missed — e.g. Nighthawk's pool moving from
    # 192.168.223.x to 192.168.15.x). Guarded on a non-empty server tag so
    # untagged ranges never clobber each other.
    if (defined $row->{notes} && length $row->{notes}) {
        $db->dbh->do(
            "DELETE FROM dhcp_ranges
              WHERE notes = ? AND NOT (subnet_cidr = ? AND start_ip = ?)",
            undef, $row->{notes}, $row->{subnet_cidr}, $row->{start_ip});
    }
    _stamp($db, 'dhcp_ranges', $repl_from,
           'subnet_cidr = ? AND start_ip = ?',
           $row->{subnet_cidr}, $row->{start_ip});
}

sub _delete_dhcp_ranges {
    my ($db, $row) = @_;
    return unless $row->{subnet_cidr} && $row->{start_ip};
    $db->delete_dhcp_range($row->{subnet_cidr}, $row->{start_ip});
}

sub _apply_dhcp_reservations {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{ip} && $row->{mac};
    $db->upsert_dhcp_reservation(
        ip          => $row->{ip},
        mac         => $row->{mac},
        name        => $row->{name},
        subnet_cidr => $row->{subnet_cidr},
        grp         => $row->{grp},
        notes       => $row->{notes},
        updated_by  => $row->{updated_by},
    );
    _stamp($db, 'dhcp_reservations', $repl_from, 'ip = ?', $row->{ip});
}

# ---- scoped one-shot refresh (the relay's REFRESH proxy) -------------
#
# Pull ONE subnet's rows from a peer (normally the elected master) into
# the local DB, right now — the synchronous complement to the lazy
# subscribe-stream. Lets an app that needs current data (net-reserve)
# force just the subnet it is looking at, instead of a full resync.
#
# Scoped tables: addresses / dhcp_leases / dhcp_reservations by IP
# prefix, dhcp_ranges by subnet_cidr prefix. addresses.mac carries an
# FK to interfaces and a subnet-scoped pull can't ride the usual
# interfaces-first dependency order, so a bare interface row is ensured
# per MAC before its address lands. The v24 DHCP-plan tables may not
# exist on an older master — their ERR is treated as "no rows".
#
# Returns the number of rows applied. Dies on connect/protocol errors.
sub refresh_subnet {
    my (%a) = @_;
    my $db     = $a{db}     or croak "refresh_subnet: db required";
    my $peer   = $a{peer}   or croak "refresh_subnet: peer required";
    my $subnet = $a{subnet} or croak "refresh_subnet: subnet required";
    my $repl_from = $a{replicated_from};

    my $prefix = _subnet_like_prefix($subnet)
        or croak "refresh_subnet: unsupported subnet '$subnet' "
               . "(need a.b.c.d/len with len >= 8)";

    my $cli = NetMgr::Client->new(listen => $peer,
                                  timeout => $a{timeout} // 10);
    $cli->hello(consumer => "relay-refresh.$$");

    my ($rows, %seen_mac, $sub) = (0);
    for my $r (@{ $cli->snapshot(++$sub, 'addresses',
                                 where => "addr LIKE '$prefix'") }) {
        next unless $r->{mac} && $r->{addr} && $r->{family};
        $db->upsert_interface(mac => $r->{mac})
            unless $seen_mac{ lc $r->{mac} }++;
        _apply_addresses($db, $r, {}, $repl_from);
        $rows++;
    }
    for my $r (@{ $cli->snapshot(++$sub, 'dhcp_leases',
                                 where => "ip LIKE '$prefix'") }) {
        next unless $r->{mac} && $r->{ip};
        $db->upsert_interface(mac => $r->{mac})
            unless $seen_mac{ lc $r->{mac} }++;
        _apply_dhcp_leases($db, $r, {}, $repl_from);
        $rows++;
    }
    my $resv = eval { $cli->snapshot(++$sub, 'dhcp_reservations',
                                     where => "ip LIKE '$prefix'") } || [];
    for my $r (@$resv) {
        next unless $r->{ip} && $r->{mac};
        _apply_dhcp_reservations($db, $r, {}, $repl_from);
        $rows++;
    }
    my $ranges = eval { $cli->snapshot(++$sub, 'dhcp_ranges',
                                       where => "subnet_cidr LIKE '$prefix'") } || [];
    for my $r (@$ranges) {
        next unless $r->{subnet_cidr} && $r->{start_ip} && $r->{end_ip};
        _apply_dhcp_ranges($db, $r, {}, $repl_from);
        $rows++;
    }
    eval { $cli->bye };
    return $rows;
}

# "a.b.c.d/len" → SQL LIKE prefix on the containing octet boundary.
# A non-octet-aligned length rounds DOWN to the wider boundary — the
# pull over-fetches a superset, which is harmless for upserts. The
# same prefix also matches dhcp_ranges.subnet_cidr ("a.b.c.0/24").
sub _subnet_like_prefix {
    my ($s) = @_;
    return undef unless defined $s
        && $s =~ m{\A(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)\z};
    my ($a, $b, $c, $d, $len) = ($1, $2, $3, $4, $5);
    return undef if grep { $_ > 255 } $a, $b, $c, $d;
    return "$a.$b.$c.%" if $len >= 24;
    return "$a.$b.%"    if $len >= 16;
    return "$a.%"       if $len >= 8;
    return undef;       # wider than /8: too broad for a "scoped" pull
}

sub _delete_hostnames {
    my ($db, $row) = @_;
    return unless $row->{machine_id} && $row->{name};
    $db->delete_hostname($row->{machine_id}, $row->{name});
}

sub _apply_mesh_tunnels {
    my ($db, $row, $idmap, $repl_from) = @_;
    return unless $row->{owner_node} && $row->{kind};
    $db->upsert_mesh_tunnel(
        owner_node      => $row->{owner_node},
        kind            => $row->{kind},
        provider_id     => $row->{provider_id},
        server_v4       => $row->{server_v4},
        tunnel_prefix   => $row->{tunnel_prefix},
        routed_prefix   => $row->{routed_prefix},
        notes           => $row->{notes},
        secret_name     => $row->{secret_name},
        replicated_from => $repl_from,
    );
}

sub _delete_mesh_tunnels {
    my ($db, $row) = @_;
    return unless $row->{owner_node} && $row->{kind};
    $db->delete_mesh_tunnel($row->{owner_node}, $row->{kind});
}

1;
