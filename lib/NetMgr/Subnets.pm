package NetMgr::Subnets;
# Subnet display names ("DMZ", "Internal", ...). Parses zone tags from
# /etc/net-mgr/dhcp.master comments by default and merges with any
# explicit overrides in /etc/net-mgr/subnets.
#
# /etc/net-mgr/subnets format: one entry per line
#   192.168.223.0/24  Internal   home
# Columns: CIDR, name, [zone-tag]. '#' comments, blank lines ignored.

use strict;
use warnings;
use Exporter 'import';
use NetMgr::Producer::DhcpMaster;

our @EXPORT_OK = qw(load lookup name_for cidr_for all);

my %ZONE_TO_NAME = (
    dmz      => 'DMZ',
    home     => 'Internal',
    jbh      => 'External',
    internal => 'Internal',
    external => 'External',
    guest    => 'Guest',
);

my %BY_CIDR;       # cidr → { cidr, net, mask, name, zone, notes }
my $loaded;

sub load {
    my (%args) = @_;
    %BY_CIDR = ();
    $loaded = 1;

    # 1. Parse dhcp.master comments.
    my $master = $args{master} // '/etc/net-mgr/dhcp.master';
    if (-f $master) {
        # Re-read raw text so we can grab the inline comment after each
        # subnet declaration (which DhcpMaster strips).
        open my $fh, '<', $master or do { warn "open $master: $!"; return };
        while (my $line = <$fh>) {
            next unless $line =~ /^\s*subnet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\d+\.\d+\.\d+\.\d+)\s*\{[^#\n]*#\s*(.*)$/;
            my ($net, $mask, $comment) = ($1, $2, $3);
            my $cidr = _cidr($net, $mask);
            my $zone;
            $zone = $1 if $comment =~ /\bzone\s*=\s*(\w+)/;
            my $name = $zone ? ($ZONE_TO_NAME{lc $zone} // ucfirst lc $zone)
                             : $comment;
            $BY_CIDR{$cidr} = {
                cidr  => $cidr, net => $net, mask => $mask,
                name  => $name, zone => $zone, notes => $comment,
            };
        }
        close $fh;
    }

    # 2. Override file.
    my $override = $args{file} // '/etc/net-mgr/subnets';
    return unless -f $override;
    open my $fh, '<', $override or return;
    while (my $line = <$fh>) {
        $line =~ s/[\r\n]+\z//;
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^#/;
        my ($cidr, $name, @rest) = split /\s+/, $line, 3;
        next unless $cidr && $name;
        my $notes = @rest ? join(' ', @rest) : undef;
        my ($net, $bits) = $cidr =~ m{^(\d+\.\d+\.\d+\.\d+)/(\d+)$}
                         ? ($1, $2) : ($cidr, 24);
        $BY_CIDR{$cidr} = {
            cidr => $cidr, net => $net, mask => _mask_from_bits($bits),
            name => $name, zone => undef, notes => $notes,
        };
    }
    close $fh;
}

sub lookup {
    my ($cidr) = @_;
    load() unless $loaded;
    return $BY_CIDR{$cidr};
}

# name_for($ip) — find the matching /24 (or wider) entry and return its name.
sub name_for {
    my ($ip) = @_;
    my $r = lookup_for_ip($ip);
    return $r ? $r->{name} : undef;
}

# cidr_for($ip) — return the matching subnet's CIDR string (or undef).
sub cidr_for {
    my ($ip) = @_;
    my $r = lookup_for_ip($ip);
    return $r ? $r->{cidr} : undef;
}

sub lookup_for_ip {
    my ($ip) = @_;
    load() unless $loaded;
    return undef unless $ip =~ /^(\d+)\.(\d+)\.(\d+)\.\d+$/;
    my $base24 = "$1.$2.$3.0/24";
    return $BY_CIDR{$base24};
}

# all() — return all known subnets as a list of { cidr, net, mask, name, ... }
sub all {
    load() unless $loaded;
    return values %BY_CIDR;
}

sub _cidr {
    my ($net, $mask) = @_;
    return "$net/" . _bits_from_mask($mask);
}

sub _bits_from_mask {
    my ($mask) = @_;
    my @oct = split /\./, $mask;
    my $bits = 0;
    for (@oct) {
        $bits += unpack '%32b*', pack 'C', $_;
    }
    return $bits;
}

sub _mask_from_bits {
    my ($bits) = @_;
    my $u = (0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF;
    return join '.', map { ($u >> (8 * (3 - $_))) & 0xFF } 0..3;
}

1;
