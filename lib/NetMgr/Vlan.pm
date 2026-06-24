package NetMgr::Vlan;
# Control-VLAN attachment: net-mgr takes ownership of an 802.1Q sub-interface
# (the "network_management" control plane) and addresses it. Used by
# NetMgr::Manager at startup so every node joins the control VLAN by default
# (opt out with [cluster] control_attach = off).
#
# The Linux interface name is the conventional <parent>.<id> (kernel IFNAMSIZ
# caps names at 15 chars, so the logical name "network_management" is carried
# only in config/logs, not as the ifname).

use strict;
use warnings;
use Exporter 'import';
use Socket qw(inet_pton inet_ntop AF_INET6);

our @EXPORT_OK = qw(derive_prefix parent_for_subnet eui64_addr attach);

# Derive a ULA /64 from an IPv4 network: fd + the first three octets in hex.
#   192.168.15.0 -> fdc0:a80f::/64   (c0.a8.0f == 192.168.15)
# Deterministic + recognisable, so the control prefix tracks the dmz subnet
# without anyone having to type it.
sub derive_prefix {
    my ($ipv4) = @_;
    return undef unless defined $ipv4 && $ipv4 =~ /^(\d+)\.(\d+)\.(\d+)\./;
    return sprintf "fd%02x:%02x%02x::/64", $1, $2, $3;
}

# parent_for_subnet([$regex]) — the physical interface carrying a v4 address in
# the wanted range (default any 192.168.*). Skips lo and existing VLAN
# sub-interfaces (names containing '.').
sub parent_for_subnet {
    my ($net_re) = @_;
    $net_re ||= qr/^192\.168\./;
    for my $line (`ip -br -4 addr show 2>/dev/null`) {
        my ($iface, undef, @addrs) = split ' ', $line;
        next if !defined $iface || $iface eq 'lo' || $iface =~ /\./;
        for my $a (@addrs) {
            (my $ip = $a) =~ s|/.*||;
            return $iface if $ip =~ $net_re;
        }
    }
    return undef;
}

# eui64_addr($mac, $prefix_cidr) — the SLAAC-style address: the prefix's top 64
# bits + an interface id built from the MAC (insert ff:fe, flip the U/L bit).
#   ("f0:bf:97:03:56:b7", "fdc0:a80f::/64") -> "fdc0:a80f::f2bf:97ff:fe03:56b7"
sub eui64_addr {
    my ($mac, $prefix_cidr) = @_;
    return undef unless defined $mac && defined $prefix_cidr;
    my ($net) = $prefix_cidr =~ m{^(.+?)/} ? ($1) : ($prefix_cidr);
    my @b = map { hex } grep { length } split /[:\-]/, $mac;
    return undef unless @b == 6;
    $b[0] ^= 0x02;                                   # flip the universal/local bit
    my @iid = ($b[0], $b[1], $b[2], 0xff, 0xfe, $b[3], $b[4], $b[5]);
    my $np = inet_pton(AF_INET6, $net) or return undef;
    return inet_ntop(AF_INET6, substr($np, 0, 8) . pack('C8', @iid));
}

# attach(%opts) — ensure the control-VLAN sub-interface exists, is up, and is
# addressed. Idempotent (safe to call every startup). opts:
#   parent  physical interface (required)
#   id      802.1Q tag        (required; must match the switch trunk)
#   prefix  control prefix CIDR (for eui64 / SLAAC plen)
#   addr    'slaac' (default) | 'eui64' | a static address literal
#   name    logical name (for logs only)
#   log     coderef($msg)
#   run     coderef(@argv)->bool  (mutating ip/sysctl calls; injectable for tests)
# Returns ($ifname, $address_or_undef, $error_or_undef). SLAAC returns a
# defined ifname with an undef address (it arrives asynchronously via RA).
sub attach {
    my (%o) = @_;
    my $parent = $o{parent};
    return (undef, undef, 'no parent interface') unless $parent;
    my $id = $o{id};
    return (undef, undef, 'no vlan id') unless defined $id && $id =~ /^\d+$/;

    my $ifname = $o{ifname} || "$parent.$id";
    my $log = $o{log} || sub {};
    my $run = $o{run} || sub { system(@_) == 0 };
    my $name = $o{name} || $ifname;

    # 1. the link
    unless (`ip -o link show $ifname 2>/dev/null`) {
        $run->('ip', 'link', 'add', 'link', $parent,
               'name', $ifname, 'type', 'vlan', 'id', $id)
            or return ($ifname, undef, "ip link add $ifname failed");
        $log->("control-vlan: created $ifname (802.1Q id $id on $parent) [$name]");
    }
    $run->('ip', 'link', 'set', $ifname, 'up');

    # 2. addressing
    my $mode   = $o{addr} || 'slaac';
    my $prefix = $o{prefix};
    if ($mode eq 'slaac') {
        # accept_ra=2 = honour RA even though forwarding may be on
        $run->('sysctl', '-qw', "net.ipv6.conf.$ifname.accept_ra=2");
        $log->("control-vlan: $ifname SLAAC — address will come from RA");
        return ($ifname, undef, undef);
    }

    my $addr;
    if ($mode eq 'eui64') {
        my $mac = _mac_of($ifname);
        $addr = eui64_addr($mac, $prefix) if $mac && $prefix;
        return ($ifname, undef, 'eui64: missing mac or prefix') unless $addr;
    } else {
        ($addr = $mode) =~ s|/.*||;          # static literal
    }
    my $plen = ($prefix && $prefix =~ m{/(\d+)}) ? $1 : 64;
    my $have = `ip -6 -o addr show dev $ifname 2>/dev/null`;
    if (index($have, $addr) < 0) {
        # nodad: the address is self-assigned and unique (EUI-64 / operator
        # static), so skip Duplicate Address Detection — otherwise it sits
        # "tentative" for ~1s and the listener that binds it right after fails
        # with EADDRNOTAVAIL.
        $run->('ip', '-6', 'addr', 'add', "$addr/$plen", 'dev', $ifname, 'nodad')
            or return ($ifname, undef, "ip addr add $addr failed");
        $log->("control-vlan: $ifname addr $addr/$plen ($mode)");
    }
    return ($ifname, $addr, undef);
}

sub _mac_of {
    my ($if) = @_;
    open my $fh, '<', "/sys/class/net/$if/address" or return undef;
    my $m = <$fh>;
    close $fh;
    chomp $m if defined $m;
    return $m;
}

1;
