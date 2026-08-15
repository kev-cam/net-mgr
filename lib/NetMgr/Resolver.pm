package NetMgr::Resolver;
# Name → IP resolution against the net-mgr DB.
#
# resolve($db, $name, %opts) → list of $ip strings (highest-quality first).
# Optional opts:
#   from_ip   => $caller_ip   — used to compute the caller's subnet so the
#                                resolver can prefer addresses on the same
#                                subnet as the caller.
#   from_cidr => '192.168.x.0/24' — explicit caller subnet (overrides from_ip)
#   family    => 'v4' | 'v6'  — restrict to one family (default 'v4')
#   limit     => N            — max addresses to return (default 8)
#
# Resolution order (per the user spec):
#   1. Direct hit in `aliases` table on $name → use its preferred-subnet
#      address of the linked machine, or any if NULL.
#   2. Hostnames LIKE '<name>-%' whose machine has an address in the
#      caller's subnet → return those subnet-local addresses.
#   3. Hostname == '<name>' → return the linked machine's addresses,
#      preferring those in the caller's subnet.
#   4. Empty list ⇒ caller (e.g. DNS server) forwards to upstream.
#
# Within every step the answers are RANKED for the client that asked, rather
# than returned in whatever order the database produced them. A multi-homed
# host is the normal case here — nas3 answers on two segments as nas3-up and
# nas3-down — and the useful answer depends entirely on where the query came
# from. We cannot read the client's routing table; what we do know is the
# segment it reached us from and what the fleet has measured about each
# address, so ranking prefers, in order: an address on the client's own
# segment (no router in the path), then one recently observed alive, then the
# lowest measured RTT. An address never observed at all is offered last. See
# _rank() for the weights.

use strict;
use warnings;
use Carp qw(croak);
use NetMgr::Subnets;

sub resolve {
    my ($db, $name, %opts) = @_;
    croak "db required" unless $db;
    croak "name required" unless defined $name && length $name;

    my $family = $opts{family} // 'v4';
    my $limit  = $opts{limit}  // 8;

    my $from_cidr = $opts{from_cidr};
    if (!$from_cidr && $opts{from_ip}) {
        NetMgr::Subnets::load();
        $from_cidr = NetMgr::Subnets::cidr_for($opts{from_ip});
    }

    my @hits;

    # 1. Aliases — explicit override.
    {
        my $a = $db->{dbh}->selectrow_hashref(
            "SELECT * FROM aliases WHERE name = ?", undef, $name);
        if ($a) {
            push @hits,
                _addresses_for_machine($db, $a->{machine_id},
                    prefer_cidr => $a->{prefer_subnet_cidr} // $from_cidr,
                    family => $family);
            return _trim(\@hits, $limit) if @hits;
        }
    }

    # 2. <name>-* hostnames — the per-segment names. This is what lets a query
    #    for `nas3` answer with nas3-up's address to a client on the `up`
    #    segment and nas3-down's to one on the `down` segment: the client never
    #    has to know which leg it is on. Containment is now decided by mask, not
    #    by matching the first three octets of the address as a string, so a
    #    segment that is not a /24 is handled correctly. Results are ranked, so
    #    among several same-segment addresses the liveliest/fastest leads.
    if ($from_cidr) {
        my $rows = $db->{dbh}->selectall_arrayref(
            "SELECT DISTINCT a.addr, a.last_observed, a.min_rtt_ms, a.last_rtt_ms
               FROM hostnames  h
               JOIN interfaces i ON i.machine_id = h.machine_id
               JOIN addresses  a ON a.mac = i.mac
              WHERE h.name LIKE CONCAT(?, '-%')
                AND a.family = ?",
            { Slice => {} }, $name, $family);
        my @local = grep { _in_cidr($_->{addr}, $from_cidr) } @$rows;
        push @hits, _rank(\@local, $from_cidr);
        return _trim(\@hits, $limit) if @hits;
    }

    # 3. Exact name match — pick the right address based on caller's subnet.
    {
        my $rows = $db->{dbh}->selectall_arrayref(
            "SELECT DISTINCT h.machine_id
               FROM hostnames h
              WHERE h.name = ?",
            { Slice => {} }, $name);
        for my $r (@$rows) {
            push @hits, _addresses_for_machine($db, $r->{machine_id},
                prefer_cidr => $from_cidr, family => $family);
        }
        # Also: check if name matches a machines.primary_name directly.
        my $pr = $db->{dbh}->selectall_arrayref(
            "SELECT id FROM machines WHERE primary_name = ?",
            { Slice => {} }, $name);
        for my $r (@$pr) {
            push @hits, _addresses_for_machine($db, $r->{id},
                prefer_cidr => $from_cidr, family => $family);
        }
    }

    return _trim(\@hits, $limit);
}

# Reverse lookup: $ip → list of names (from hostnames + aliases).
sub reverse_lookup {
    my ($db, $ip) = @_;
    my @names;
    my $rows = $db->{dbh}->selectall_arrayref(
        "SELECT DISTINCT h.name
           FROM addresses  a
           JOIN interfaces i ON i.mac = a.mac
           JOIN hostnames  h ON h.machine_id = i.machine_id
          WHERE a.addr = ?",
        { Slice => {} }, $ip);
    push @names, $_->{name} for @$rows;
    my $alias = $db->{dbh}->selectall_arrayref(
        "SELECT DISTINCT al.name
           FROM aliases    al
           JOIN interfaces i ON i.machine_id = al.machine_id
           JOIN addresses  a ON a.mac = i.mac
          WHERE a.addr = ?",
        { Slice => {} }, $ip);
    push @names, $_->{name} for @$alias;
    my %seen;
    return grep { !$seen{$_}++ } @names;
}

# Is $ip inside $cidr? Real mask arithmetic, not a string prefix. The previous
# comparison took the first three octets of the CIDR and matched addresses
# starting with them, which silently assumes every network is a /24: on a /23 it
# drops half the range, and on a /16 it matches almost nothing.
sub _in_cidr {
    my ($ip, $cidr) = @_;
    return 0 unless defined $ip && defined $cidr;
    my ($net, $bits) = $cidr =~ m{^(\d+\.\d+\.\d+\.\d+)/(\d+)$} or return 0;
    my $to_i = sub {
        my @o = split /\./, ($_[0] // '');
        return undef unless @o == 4;
        return ($o[0] << 24) + ($o[1] << 16) + ($o[2] << 8) + $o[3];
    };
    my ($a, $n) = ($to_i->($ip), $to_i->($net));
    return 0 unless defined $a && defined $n;
    my $mask = $bits == 0 ? 0 : ((0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF);
    return (($a & $mask) == ($n & $mask)) ? 1 : 0;
}

sub _age_seconds {
    my ($dt) = @_;
    my @t = ($dt // '') =~ /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/
        or return undef;
    require Time::Local;
    my $e = eval { Time::Local::timelocal($t[5], $t[4], $t[3], $t[2], $t[1] - 1, $t[0]) };
    return defined $e ? (time - $e) : undef;
}

# Rank candidate addresses for the client that asked.
#
# The old order was `ORDER BY a.addr` — alphabetical, so effectively arbitrary —
# with the caller's subnet floated to the front. That answers "which subnet" but
# never "which of these actually works", so a long-dead address that happened to
# sort first was handed out ahead of a live one. We cannot see the client's
# routing table; we only know which segment it reached us from, plus what the
# fleet has measured. Both are used:
#
#   +8  same subnet as the client — reachable across the local segment with no
#       router in the path. This is what makes a query for `nas3` answer with
#       the .15 address for a .15 client and the .223 address for a .223 one.
#   +3  observed alive within the hour
#   +1  observed alive within the day
#   -6  never observed — a paper record from a config import, which may not
#       exist at all. Still offered, but last, so it is used only when there is
#       nothing better.
# Ties break on lowest observed RTT (the "fastest" part of the request), then
# most recently seen, then the address itself so answers stay stable.
sub _rank {
    my ($rows, $from_cidr) = @_;
    my @scored;
    for my $r (@$rows) {
        next unless defined $r->{addr};
        my $s = 0;
        $s += 8 if $from_cidr && _in_cidr($r->{addr}, $from_cidr);
        if (defined $r->{last_observed} && length $r->{last_observed}) {
            my $age = _age_seconds($r->{last_observed});
            $s += 3 if defined $age && $age <= 3600;
            $s += 1 if defined $age && $age <= 86400;
        } else {
            $s -= 6;
        }
        my $rtt = defined $r->{min_rtt_ms}  ? $r->{min_rtt_ms}
                : defined $r->{last_rtt_ms} ? $r->{last_rtt_ms}
                :                             9999;
        push @scored, [ $s, $rtt, ($r->{last_observed} // ''), $r->{addr} ];
    }
    @scored = sort {
           $b->[0] <=> $a->[0]
        || $a->[1] <=> $b->[1]
        || $b->[2] cmp $a->[2]
        || $a->[3] cmp $b->[3]
    } @scored;
    my %seen;
    return grep { !$seen{$_}++ } map { $_->[3] } @scored;
}

# Internal: a machine's addresses, best-first for this client.
sub _addresses_for_machine {
    my ($db, $mid, %opts) = @_;
    my $family = $opts{family} // 'v4';
    my $rows = $db->{dbh}->selectall_arrayref(
        "SELECT DISTINCT a.addr, a.last_observed, a.min_rtt_ms, a.last_rtt_ms
           FROM interfaces i
           JOIN addresses  a ON a.mac = i.mac
          WHERE i.machine_id = ? AND a.family = ?",
        { Slice => {} }, $mid, $family);
    return _rank($rows, $opts{prefer_cidr});
}

sub _trim {
    my ($hits, $limit) = @_;
    my %seen;
    my @uniq = grep { defined && !$seen{$_}++ } @$hits;
    splice @uniq, $limit if @uniq > $limit;
    return @uniq;
}

1;
