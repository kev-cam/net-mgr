package NetMgr::Multi;
# Fan-out wrapper around N NetMgr::Client connections — the foundation
# for cluster-aware admin tools (net-cluster CLI, and the future Tk
# GUI). One instance holds a Client per peer, exposes status/snapshot/
# observe in *_all forms, and can compute per-row divergence across the
# fleet.
#
# Construction:
#   my $m = NetMgr::Multi->new(
#       peers   => [ 'kc-qernel', 'nas3', 'gateway3:7531',
#                    { name => 'zmc1', listen => '192.168.15.163:7531' } ],
#       timeout => 3,
#       auth    => {},            # truthy → auth each connection
#                                 # (defaults to ssh-keygen -Y sign on
#                                 #  ~/.ssh/id_ed25519); pass keys to
#                                 #  override.
#   );
#   $m->connect_all;
#
# Or autodiscover from the local daemon:
#   my $m = NetMgr::Multi->discover(seed => '127.0.0.1:7531');
#
# Reads:
#   $m->status_all                 # { name => status_kv }
#   $m->snapshot_all($table, where => '...')
#                                  # { name => { rows => [...] | error => '...' } }
#   $m->diff_table($table,
#                  key => ['col', ...],
#                  where => '...') # arrayref of {key, values, diverges}
#   $m->master                     # peer hashref or undef
#
# Writes:
#   $m->observe_all(kind => 'friendly_name', ...) # { name => reply_line }
#   $m->observe_one($peer_name, kind => ...)      # single-peer fan-out
#
# v1 is sequential — for ~5-10 peers on a LAN the per-op RTT is single-
# digit ms each. Per-peer connect timeout caps worst-case slow start at
# (timeout * dead_peers). Parallelism (fork-per-peer or AnyEvent) is a
# v2 problem; the API doesn't change.

use strict;
use warnings;
use Carp qw(croak carp);
use NetMgr::Client;

sub new {
    my ($class, %args) = @_;
    my @peers;
    for my $p (@{ $args{peers} || [] }) {
        push @peers, _normalize_peer($p);
    }
    croak "NetMgr::Multi: no peers" unless @peers;
    return bless {
        peers    => \@peers,    # [ { name, listen, client?, error?,
                                #     authed?, auth_error? } ]
        timeout  => $args{timeout}  // 3,
        auth     => $args{auth},
        consumer => $args{consumer} // "multi.$$",
    }, $class;
}

# Bootstrap from one seed daemon: ask it for cluster_members in STATUS
# and build the peer list from that. The seed itself is *not* added
# automatically — callers usually want their local daemon included via
# 127.0.0.1, which is what the seed already is when omitted.
sub discover {
    my ($class, %args) = @_;
    my $seed = $args{seed} // '127.0.0.1:7531';
    my $cli = NetMgr::Client->new(listen => $seed, timeout => $args{timeout} // 3);
    $cli->hello(consumer => "multi-discover.$$");
    my $st = $cli->status || {};
    $cli->bye;
    my $members = $st->{cluster_members} // '';
    my $self_name = $st->{cluster_member} // '';
    my @names;
    for my $m (split /[,\s]+/, $members) {
        next unless length $m;
        push @names, $m;
    }
    # Always include self even if cluster_members is empty (single-
    # node setup is the common dev case). Resolve self → 127.0.0.1
    # so we hit the local daemon by its loopback bind instead of a
    # potentially mid-flap external address.
    my @peers;
    if (@names) {
        for my $n (@names) {
            if ($n eq $self_name) {
                push @peers, { name => $n, listen => $seed };
            } else {
                push @peers, _normalize_peer($n);
            }
        }
    } else {
        push @peers, { name => ($self_name || 'local'), listen => $seed };
    }
    return $class->new(peers => \@peers,
                       timeout  => $args{timeout},
                       auth     => $args{auth},
                       consumer => $args{consumer});
}

sub peers { return @{ $_[0]->{peers} } }

# Look up a peer by name (case-sensitive match against ->{name}).
sub peer {
    my ($self, $name) = @_;
    for my $p (@{ $self->{peers} }) {
        return $p if $p->{name} eq $name;
    }
    return undef;
}

# Open + HELLO every peer, optionally AUTH. Per-peer failures are
# captured in $p->{error} / $p->{auth_error}; the caller keeps going
# with whichever subset connected.
sub connect_all {
    my ($self) = @_;
    for my $p (@{ $self->{peers} }) {
        my $cli = eval {
            NetMgr::Client->new(listen => $p->{listen},
                                timeout => $self->{timeout});
        };
        if (!$cli) {
            my $err = $@ || 'unknown'; chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
            $p->{error} = "connect: $err";
            $p->{client} = undef;
            next;
        }
        eval { $cli->hello(consumer => $self->{consumer}) };
        if ($@) {
            my $err = $@; chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
            $p->{error} = "hello: $err";
            eval { $cli->bye };
            next;
        }
        $p->{client} = $cli;
        delete $p->{error};

        if ($self->{auth}) {
            eval { $cli->auth(%{ $self->{auth} }) };
            if ($@) {
                my $err = $@; chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
                $p->{auth_error} = $err;
            } else {
                $p->{authed} = 1;
            }
        }
    }
    return $self;
}

# STATUS fan-out. Returns { name => kv } for every connected peer;
# unconnected peers are omitted (their $p->{error} still has the why).
sub status_all {
    my ($self) = @_;
    my %out;
    for my $p (@{ $self->{peers} }) {
        next unless $p->{client};
        my $st = eval { $p->{client}->status };
        $out{ $p->{name} } = $st if defined $st;
    }
    return \%out;
}

# Returns the peer hashref whose STATUS reports cluster_role=master,
# or undef. Lets callers route master-only writes ('replicated'
# tables: friendly_names, hostnames, aliases, dhcp_vars…) to the right
# place without baking the master name into config.
sub master {
    my ($self) = @_;
    my $st = $self->status_all;
    for my $p (@{ $self->{peers} }) {
        my $s = $st->{ $p->{name} } or next;
        return $p if ($s->{cluster_role} // '') eq 'master';
    }
    return undef;
}

# Snapshot a table on every connected peer. Each peer's reply is a
# hashref: { rows => [...] } on success, { error => '...' } on
# server-side error (bad WHERE, unknown table, …). sub_id is per-
# connection so reusing the same number across peers is safe.
sub snapshot_all {
    my ($self, $table, %args) = @_;
    my %out;
    my $sub_id = $args{sub_id} // 1 + int(rand(1 << 30));
    for my $p (@{ $self->{peers} }) {
        next unless $p->{client};
        my @snap_args;
        push @snap_args, (where => $args{where}) if defined $args{where};
        my $rows = eval { $p->{client}->snapshot($sub_id, $table, @snap_args) };
        if ($@) {
            my $err = $@; chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
            $out{ $p->{name} } = { error => $err };
        } else {
            # ROW lines carry op/sub/table as wire envelope alongside
            # actual columns; strip so the row hash is just the row.
            for my $r (@$rows) {
                delete @{$r}{qw(op sub table mode)};
            }
            $out{ $p->{name} } = { rows => $rows };
        }
    }
    return \%out;
}

# Single-peer OBSERVE — primarily for master-only writes.
sub observe_one {
    my ($self, $peer_name, %kv) = @_;
    my $p = $self->peer($peer_name) or croak "no such peer: $peer_name";
    return "ERR not connected" unless $p->{client};
    my $r = eval { $p->{client}->observe(%kv) };
    if ($@) {
        my $err = $@; chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
        return "ERR $err";
    }
    return $r;
}

# OBSERVE fan-out to every connected peer. Returns { name => reply_line }
# where reply_line is whatever the daemon sent back ("OK", "ERR …", or
# undef on no reply). Per-peer (auth-gated) tables — peer_cap_set/clear,
# isp_link_set, lost_device_delete — are the canonical use case; for
# replicated state, prefer observe_one against master().
sub observe_all {
    my ($self, %kv) = @_;
    my %out;
    for my $p (@{ $self->{peers} }) {
        if (!$p->{client}) {
            $out{ $p->{name} } = "ERR " . ($p->{error} // 'not connected');
            next;
        }
        my $r = eval { $p->{client}->observe(%kv) };
        if ($@) {
            my $err = $@; chomp $err; $err =~ s/ at \S+ line \d+\.?\z//;
            $out{ $p->{name} } = "ERR $err";
        } else {
            $out{ $p->{name} } = $r // 'ERR no reply';
        }
    }
    return \%out;
}

# Per-peer state diff. Caller names which columns form the row's
# logical key (e.g. ['name','machine_id'] for friendly_names). Returns
# an arrayref of:
#   { key => "v1\0v2", values => { peer => row_hash | undef }, diverges => 0|1 }
# 'diverges' is 1 when either some peer is missing the row OR two peers
# disagree on a non-key, non-volatile column.
sub diff_table {
    my ($self, $table, %args) = @_;
    my @keys = @{ $args{key} || ['id'] };

    # Columns whose values are legitimately per-peer (timestamps the
    # producer stamped locally, RTT/loss measurements, etc). Always
    # excluded from the divergence comparison. Callers can extend.
    my %ignore = (map { $_ => 1 } @{ $args{ignore} || [] });
    $ignore{$_} = 1 for qw(
        last_observed first_observed observed_at created_at updated_at
        last_seen first_seen last_reply
        min_rtt_ms last_rtt_ms loss_pct link_speed_mbps
        replicated_from
    );

    my $snap = $self->snapshot_all($table,
                                   ($args{where} ? (where => $args{where}) : ()));

    my %grid;     # key_string => { peer_name => row }
    for my $peer_name (sort keys %$snap) {
        my $r = $snap->{$peer_name};
        next if !$r || $r->{error};
        for my $row (@{ $r->{rows} || [] }) {
            my $k = join("\0", map { defined $row->{$_} ? $row->{$_} : '' } @keys);
            $grid{$k}{$peer_name} = $row;
        }
    }

    my @connected = map { $_->{name} } grep { $_->{client} } @{ $self->{peers} };

    my @diffs;
    for my $k (sort keys %grid) {
        my %cells;
        my $missing = 0;
        for my $name (@connected) {
            if (exists $grid{$k}{$name}) {
                $cells{$name} = $grid{$k}{$name};
            } else {
                $cells{$name} = undef;
                $missing++;
            }
        }
        my $diverges = $missing > 0
                    || _values_differ([ grep { defined } values %cells ],
                                      \%ignore, [@keys]);
        push @diffs, {
            key      => $k,
            key_cols => [@keys],
            values   => \%cells,
            diverges => $diverges ? 1 : 0,
        };
    }
    return \@diffs;
}

# Returns true if any two rows disagree on a column that isn't a key
# or in the ignore set.
sub _values_differ {
    my ($rows, $ignore, $keys) = @_;
    return 0 if @$rows < 2;
    my %key_col = map { $_ => 1 } @$keys;
    my $first = $rows->[0];
    for my $r (@{$rows}[1 .. $#$rows]) {
        my %seen_col;
        for my $col (keys %$first, keys %$r) {
            next if $seen_col{$col}++;
            next if $key_col{$col} || $ignore->{$col};
            my $a = $first->{$col};
            my $b = $r->{$col};
            $a = '' unless defined $a;
            $b = '' unless defined $b;
            return 1 if $a ne $b;
        }
    }
    return 0;
}

sub bye_all {
    my ($self) = @_;
    for my $p (@{ $self->{peers} || [] }) {
        if ($p->{client}) {
            eval { $p->{client}->bye };
            $p->{client} = undef;
        }
    }
    return 1;
}

sub DESTROY {
    my ($self) = @_;
    eval { $self->bye_all };
}

# --- internals ------------------------------------------------------

# Accepts the loose forms commonly typed on the command line:
#   'host'                          → name=host, listen=host:7531
#   'host:port'                     → name=host, listen=host:port
#   'name=host:port'                → split on the first '='
#   { name => …, listen => … }      → used as-is (listen defaulted)
sub _normalize_peer {
    my ($p) = @_;
    if (ref $p eq 'HASH') {
        my %h = %$p;
        croak "peer hash needs name= or listen="
            unless defined $h{name} || defined $h{listen};
        $h{listen} //= "$h{name}:7531";
        if (!defined $h{name}) {
            (my $n = $h{listen}) =~ s/:\d+$//;
            $h{name} = $n;
        }
        return \%h;
    }
    croak "peer must be string or hashref" if ref $p;
    if ($p =~ /^([^=]+)=(.+)$/) {
        return { name => $1, listen => $2 };
    }
    if ($p =~ /:\d+$/) {
        (my $n = $p) =~ s/:\d+$//;
        return { name => $n, listen => $p };
    }
    return { name => $p, listen => "$p:7531" };
}

1;
