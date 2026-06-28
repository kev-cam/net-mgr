package NetMgr::AutoDiscover;
# Auto-discover cluster members from a zone spec. Replaces the
# manual `[cluster] members = a,b,c` list when the operator writes
# `members = auto[:ZONE_CLASS[/ZONE_NAME]]` instead.
#
# Discovery flow:
#   1. Parse the spec.
#   2. If a zone was named, look up this host's interface_zones rows
#      matching that zone and collect their CIDRs.
#   3. Pull every host from the local `peers` table (populated by
#      net-find-peers — it's already a list of port-7531-responding
#      net-mgr instances on the LAN).
#   4. Keep only peers whose IP falls inside one of the zone CIDRs
#      (no filter applied when `auto` is bare).
#   5. Resolve each peer IP to a member name (hostname's first label)
#      via the local hostnames table first, falling back to reverse
#      DNS. Drop peers we can't name.
#
# Returns an arrayref of distinct member names, excluding self. The
# caller (Manager) hands this to Mesh.set_members().
#
# No active probing in this module — all the network work (port-7531
# scan, STATUS check) is already done by net-find-peers, which writes
# to the peers table. This keeps discovery cheap enough to run every
# few minutes from the main loop without blocking it noticeably.

use strict;
use warnings;
use Socket qw(inet_pton inet_aton AF_INET);
# gethostbyaddr is a core function in main:: — no import needed.

sub parse_spec {
    my ($s) = @_;
    return undef unless defined $s;
    return undef unless $s =~ /^\s*auto(?:\s*:\s*([^\/\s]+)(?:\s*\/\s*(\S+))?)?\s*$/i;
    return {
        mode       => 'auto',
        zone_class => $1,         # may be undef → no zone filter
        zone_name  => $2,
    };
}

sub discover {
    my (%args) = @_;
    my $db        = $args{db}        or die "discover: db required";
    my $spec      = $args{spec}      or die "discover: spec required";
    my $self_name = $args{self_name};
    my $self_host = $args{self_host} // $self_name;
    my $port      = $args{port} // 7531;
    my $log       = $args{log}       // sub {};

    # 1. Resolve zone → CIDRs (or empty == no filter)
    my @cidrs;
    if (defined $spec->{zone_class}) {
        my $sql = "SELECT cidr FROM interface_zones
                   WHERE host = ? AND zone_class = ?";
        my @binds = ($self_host, $spec->{zone_class});
        if (defined $spec->{zone_name}) {
            $sql .= " AND zone_name = ?";
            push @binds, $spec->{zone_name};
        }
        my $rows = $db->dbh->selectall_arrayref($sql, { Slice => {} }, @binds);
        @cidrs = map { $_->{cidr} } @$rows;
        if (!@cidrs) {
            $log->("auto-discover: no interface_zones rows for "
                 . _spec_desc($spec) . " on $self_host");
            return [];
        }
    }

    # 2. Candidate peers from local peers table (carry cluster_member if
    # find-peers stored one — that bypasses the machines/hostnames join + PTR
    # fallback, which often fail on a fresh follower whose DB is empty).
    my $peer_rows = $db->dbh->selectall_arrayref(
        "SELECT host, port, cluster_member FROM peers WHERE port = ?",
        { Slice => {} }, $port,
    );

    # 3. CIDR filter + name resolution. Pick the peer's stored cluster_member
    # first (cheap + reliable), fall back to the machines/hostnames join,
    # finally PTR.
    my @names;
    my %seen;
    for my $r (@$peer_rows) {
        my $ip = $r->{host};
        next unless _looks_like_v4($ip);
        next if @cidrs && !_ip_in_any_cidr($ip, \@cidrs);
        my $name = (defined $r->{cluster_member} && length $r->{cluster_member})
                   ? _first_label($r->{cluster_member})
                   : _name_for_ip($db, $ip);
        next unless defined $name && length $name;
        next if defined $self_name && $name eq $self_name;
        next if $seen{$name}++;
        push @names, $name;
    }
    $log->("auto-discover: " . _spec_desc($spec)
         . " → " . scalar(@names) . " peer(s): "
         . (@names ? join(',', @names) : '-'));
    return \@names;
}

sub _spec_desc {
    my ($s) = @_;
    my $c = $s->{zone_class};
    my $n = $s->{zone_name};
    return 'auto (no zone filter)' unless defined $c;
    return "auto:$c" . (defined $n ? "/$n" : '');
}

# Look up a *canonical* name for an IP. The point is to dedupe peers
# that have multiple interfaces (e.g. nas3 has nas3-up + nas3-down +
# nas3-dwn2; we want one mesh entry "nas3", not three). Strategy:
#   1. machines.primary_name           — definitive single name per box
#   2. shortest hostnames.name         — bias toward bare 'nas3' over
#                                        the interface-suffix variants
#   3. PTR DNS reverse, first label    — last resort
sub _name_for_ip {
    my ($db, $ip) = @_;
    my $dbh = $db->dbh;

    # 1. machines.primary_name
    my $row = $dbh->selectrow_arrayref(
        "SELECT m.primary_name FROM machines m
         JOIN interfaces i ON i.machine_id = m.id
         JOIN addresses a  ON i.mac        = a.mac
         WHERE a.addr = ? AND m.primary_name IS NOT NULL
                          AND m.primary_name <> ''
         LIMIT 1", undef, $ip);
    return _first_label($row->[0]) if $row && defined $row->[0];

    # 2. Shortest hostname — collapses nas3 / nas3-up / nas3-down /
    # nas3-dwn2 down to nas3. CHAR_LENGTH works on both MySQL and
    # MariaDB; SQLite would need LENGTH but that's not a concern here.
    $row = $dbh->selectrow_arrayref(
        "SELECT h.name FROM hostnames h
         JOIN interfaces i ON h.machine_id = i.machine_id
         JOIN addresses a  ON i.mac        = a.mac
         WHERE a.addr = ? AND h.name IS NOT NULL AND h.name <> ''
         ORDER BY CHAR_LENGTH(h.name) ASC, h.last_seen DESC
         LIMIT 1", undef, $ip);
    return _first_label($row->[0]) if $row && defined $row->[0];

    # 3. PTR — gethostbyaddr is synchronous; usually a DNS cache hit.
    my $packed = inet_aton($ip) or return undef;
    my $ptr = gethostbyaddr($packed, AF_INET);
    return _first_label($ptr) if defined $ptr && length $ptr;
    return undef;
}

sub _first_label {
    my ($s) = @_;
    return undef unless defined $s && length $s;
    $s = lc $s;
    $s =~ s/\..*//;
    return $s;
}

sub _looks_like_v4 {
    my ($s) = @_;
    return defined inet_pton(AF_INET, $s);
}

sub _ip_in_any_cidr {
    my ($ip, $cidrs) = @_;
    my $ipi = _ip_to_int($ip) // return 0;
    for my $c (@$cidrs) {
        next unless $c =~ m{^(\d+\.\d+\.\d+\.\d+)/(\d+)$};
        my ($net, $bits) = ($1, $2);
        my $ni = _ip_to_int($net) // next;
        my $mask = $bits == 0 ? 0
                              : ((0xffffffff << (32 - $bits)) & 0xffffffff);
        return 1 if ($ipi & $mask) == ($ni & $mask);
    }
    return 0;
}

sub _ip_to_int {
    my ($s) = @_;
    return undef unless $s =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    return ($1 << 24) | ($2 << 16) | ($3 << 8) | $4;
}

1;
