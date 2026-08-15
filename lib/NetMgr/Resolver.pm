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

    # 1b. <host>-<subnet-name>: ask for a host ON a named subnet and get the
    #     address it is CURRENTLY using there — e.g. u32u-dmz is u32u's live
    #     address on the subnet named "dmz". This is synthesised from the subnet
    #     naming rather than requiring a stored hostname per leg, so it keeps
    #     working when a device moves within that subnet (a new DHCP lease
    #     changes the address, not the name). Only addresses actually observed
    #     are eligible: the question "where is it now" has no useful answer from
    #     a paper record that no producer has ever seen respond.
    #
    #     Subnet names come from dhcp_ranges.zone, which is cluster-replicated
    #     and already settable via `net-reserve add-range --zone`.
    if ($name =~ /^(.+)-([A-Za-z0-9]+)$/) {
        my ($host, $zone) = ($1, $2);
        my $cidrs = $db->{dbh}->selectcol_arrayref(
            "SELECT DISTINCT subnet_cidr FROM dhcp_ranges
              WHERE zone IS NOT NULL AND zone <> '' AND LOWER(zone) = LOWER(?)",
            undef, $zone);
        if ($cidrs && @$cidrs) {
            my $rows = _live_addresses_for_host($db, $host, $family);
            my @on_subnet = grep {
                my $ip = $_->{addr};
                scalar grep { _in_cidr($ip, $_) } @$cidrs;
            } @$rows;
            push @hits, _rank(\@on_subnet, $from_cidr);
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

# Addresses a host is CURRENTLY using, from both places that know.
#
# `addresses` records what producers have observed, but it lags a DHCP client
# badly: 192.168.15.179 was still filed against Patio-PC's MAC from 73 days
# earlier while u32u was answering on it, so asking that table alone for u32u
# returns nothing. `dhcp_leases` holds the binding DHCP made most recently and
# is keyed by MAC, so it survives the address changes. Two guards keep the lease
# table's history out: only each MAC's newest lease counts (it is keyed
# (mac,ip), so it retains every address a MAC ever held), and an address is
# accepted only from whichever MAC has the freshest claim on it — otherwise a
# host still answers to an address that has since moved to a different device.
sub _live_addresses_for_host {
    my ($db, $host, $family) = @_;
    my $dbh = $db->{dbh};
    # Gather every leg of the device, not just the record that carries the bare
    # name. This fleet models a host's interfaces as SEPARATE machines when they
    # were discovered separately — u32u's ethernet is machine "u32u" while its
    # WiFi is machine "u32u-air" — so a query for u32u on a WiFi subnet finds
    # nothing if we only look at the exact name. The base name identifies the
    # device; the suffix identifies a leg. Matching "<host>" plus "<host>-%"
    # collects both. The hyphen is required, so asking for wc1 does not sweep in
    # wc10 and wc11.
    my $macs = $dbh->selectcol_arrayref(
        "SELECT DISTINCT i.mac
           FROM machines   m
           JOIN interfaces i ON i.machine_id = m.id
      LEFT JOIN hostnames  h ON h.machine_id = m.id
          WHERE m.primary_name = ? OR m.primary_name LIKE CONCAT(?, '-%')
             OR h.name = ?        OR h.name        LIKE CONCAT(?, '-%')",
        undef, $host, $host, $host, $host) || [];
    return [] unless @$macs;
    my %mine = map { lc($_) => 1 } @$macs;

    my @rows;
    my $obs = $dbh->selectall_arrayref(
        "SELECT addr, mac, last_observed, min_rtt_ms, last_rtt_ms
           FROM addresses WHERE family = ? AND last_observed IS NOT NULL",
        { Slice => {} }, $family) || [];
    my %claim;      # addr => { mac, when } — freshest claim on each address
    for my $r (@$obs) {
        my $when = $r->{last_observed} // '';
        $claim{ $r->{addr} } = { mac => lc($r->{mac} // ''), when => $when }
            if !$claim{ $r->{addr} } || $when gt $claim{ $r->{addr} }{when};
        push @rows, $r if $mine{ lc($r->{mac} // '') };
    }

    if ($family eq 'v4') {
        my $leases = $dbh->selectall_arrayref(
            "SELECT mac, ip, last_seen FROM dhcp_leases", { Slice => {} }) || [];
        my %newest;
        for my $l (@$leases) {
            next unless $l->{mac} && $l->{ip};
            my ($mac, $ls) = (lc $l->{mac}, $l->{last_seen} // '');
            $newest{$mac} = { ip => $l->{ip}, when => $ls }
                if !$newest{$mac} || $ls gt $newest{$mac}{when};
        }
        for my $mac (keys %newest) {
            my ($ip, $when) = @{ $newest{$mac} }{qw(ip when)};
            $claim{$ip} = { mac => $mac, when => $when }
                if !$claim{$ip} || $when gt $claim{$ip}{when};
        }
        # Accept our lease unless somebody else's claim is STRICTLY newer. A tie
        # must not disqualify us, because lease timestamps are frequently not
        # comparable at all: the dhcp.master import rewrites last_seen on every
        # row in one pass, so on this fleet eleven different MACs hold a lease
        # for 192.168.15.179 bearing the identical second. Requiring us to be
        # the outright freshest handed those addresses to whichever MAC the hash
        # happened to yield first — which is to say, at random.
        my %have = map { ($_->{addr} // '') => 1 } @rows;
        for my $mac (grep { $mine{$_} } keys %newest) {
            my ($ip, $when) = @{ $newest{$mac} }{qw(ip when)};
            next if $have{$ip};
            next if ($claim{$ip}{when} // '') gt ($when // '');   # strictly newer wins
            push @rows, { addr => $ip, mac => $mac, last_observed => $when };
        }
    }
    return \@rows;
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
