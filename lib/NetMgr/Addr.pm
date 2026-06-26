package NetMgr::Addr;
# Endpoint (host:port) + IPv6-literal handling, and local-address enumeration.
# Shared by NetMgr::Client (connector), NetMgr::Manager (listener) and
# NetMgr::Mesh so the v6-bracket rules live in exactly one place.

use strict;
use warnings;
use Exporter 'import';
use Socket qw(inet_pton AF_INET AF_INET6);

our @EXPORT_OK = qw(split_hostport join_hostport local_addrs addr_in_prefix);

# Split an endpoint into ($host, $port), $port undef when absent. Handles:
#   host:port  -> (host, port) ;  [v6]:port -> (v6, port) ;  [v6] -> (v6, undef)
#   bare host  -> (host, undef);  bare IPv6 (2+ colons, no brackets) -> (v6, undef)
# The bracket form is the only way to attach a port to an IPv6 literal — an
# unbracketed value with multiple colons is taken as a portless v6 host.
sub split_hostport {
    my ($s) = @_;
    return (undef, undef) unless defined $s && length $s;
    return ($1, $2) if $s =~ /^\[([^\]]*)\](?::(\d+))?$/;   # [v6] / [v6]:port
    return ($1, $2) if $s =~ /^([^:]+):(\d+)$/;             # host:port
    return ($s, undef);                                     # bare host / bare v6
}

# Inverse of split_hostport: format ($host, $port) as an endpoint string,
# bracketing an IPv6 host (one containing ':'). Port omitted when undef.
sub join_hostport {
    my ($host, $port) = @_;
    my $h = (defined $host && $host =~ /:/) ? "[$host]" : ($host // '');
    return defined $port && length $port ? "$h:$port" : $h;
}

# This host's bound addresses of the given family ('v4'|'v6'), excluding lo and
# (for v6) link-local. If $prefix (a CIDR) is given, only addresses inside it.
sub local_addrs {
    my ($family, $prefix) = @_;
    my $flag = (defined $family && $family eq 'v6') ? '-6' : '-4';
    my @ips;
    for my $line (`ip -br $flag addr show 2>/dev/null`) {
        chomp $line;
        my ($iface, undef, @addrs) = split ' ', $line;
        next unless defined $iface;
        next if $iface eq 'lo';
        for my $a (@addrs) {
            $a =~ s|/.*||;                              # strip /prefixlen
            next if $flag eq '-6' && $a =~ /^fe80:/i;   # skip link-local
            push @ips, $a;
        }
    }
    @ips = grep { addr_in_prefix($_, $prefix) } @ips
        if defined $prefix && length $prefix;
    return @ips;
}

# True if $addr is inside CIDR $prefix. Family-agnostic: handles both IPv6
# ("fd12:3456:789a:1::/64") and IPv4 ("192.168.15.0/24"). The family is taken
# from $addr; a bare address (no /len) matches as a host route.
sub addr_in_prefix {
    my ($addr, $cidr) = @_;
    my $v6 = (index($addr, ':') >= 0);
    my $fam = $v6 ? AF_INET6 : AF_INET;
    my ($net, $len) = $cidr =~ m{^(.+)/(\d+)$} ? ($1, $2) : ($cidr, $v6 ? 128 : 32);
    my $a = inet_pton($fam, $addr) or return 0;
    my $n = inet_pton($fam, $net)  or return 0;
    my $bytes = int($len / 8);
    return 0 if $bytes && substr($a, 0, $bytes) ne substr($n, 0, $bytes);
    my $bits = $len % 8;
    if ($bits) {
        my $mask = (0xFF << (8 - $bits)) & 0xFF;
        return 0 if (ord(substr($a, $bytes, 1)) & $mask)
                 != (ord(substr($n, $bytes, 1)) & $mask);
    }
    return 1;
}

1;
