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

    # 2. <name>-* hostnames whose address sits in caller's subnet.
    if ($from_cidr) {
        my ($net_base) = $from_cidr =~ /^(\d+\.\d+\.\d+)\./;
        my $like_addr  = "$net_base.%";
        my $rows = $db->{dbh}->selectall_arrayref(
            "SELECT DISTINCT a.addr
               FROM hostnames  h
               JOIN interfaces i ON i.machine_id = h.machine_id
               JOIN addresses  a ON a.mac = i.mac
              WHERE h.name LIKE CONCAT(?, '-%')
                AND a.family = ?
                AND a.addr LIKE ?
              ORDER BY a.addr",
            { Slice => {} }, $name, $family, $like_addr);
        push @hits, $_->{addr} for @$rows;
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

# Internal: find a machine's addresses, preferring those in $prefer_cidr.
sub _addresses_for_machine {
    my ($db, $mid, %opts) = @_;
    my $family = $opts{family} // 'v4';
    my $rows = $db->{dbh}->selectall_arrayref(
        "SELECT DISTINCT a.addr
           FROM interfaces i
           JOIN addresses  a ON a.mac = i.mac
          WHERE i.machine_id = ? AND a.family = ?
          ORDER BY a.addr",
        { Slice => {} }, $mid, $family);
    my @all = map { $_->{addr} } @$rows;
    return @all unless $opts{prefer_cidr};
    my ($net_base) = $opts{prefer_cidr} =~ /^(\d+\.\d+\.\d+)\./;
    my @in  = grep { /^\Q$net_base\E\./ } @all;
    my @out = grep { !/^\Q$net_base\E\./ } @all;
    return (@in, @out);
}

sub _trim {
    my ($hits, $limit) = @_;
    my %seen;
    my @uniq = grep { defined && !$seen{$_}++ } @$hits;
    splice @uniq, $limit if @uniq > $limit;
    return @uniq;
}

1;
