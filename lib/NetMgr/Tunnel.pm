package NetMgr::Tunnel;
# Hurricane Electric 6in4 (SIT) tunnel — net-mgr's "he_net" IPv6 uplink.
#
# MINIMAL scope: bring the tunnel up / down. Deferred (the "extra functionality"
# debate): T-Mobile ssh-tunnel failover when there's no public IPv4, HE
# dynamic-endpoint update (set-ddns), and router glue (firewall, internal RA).
#
# Re-implements the core of the legacy /usr/local/bin/he-ipv6 on gateway3:
#   ip tunnel add <name> mode sit remote <server> local <wan-v4> ttl 255
#   ip link set <name> up
#   ip addr add <prefix>::<suffix>/64 dev <name>
#   ip route add ::/0 dev <name>
#   sysctl net.ipv6.conf.all.forwarding=1

use strict;
use warnings;
use Exporter 'import';
use Socket qw(inet_pton inet_ntop AF_INET6);

our @EXPORT_OK = qw(external_ipv4 tunnel_addr up down);

# (iface, ipv4) of the external/default-route interface — the tunnel's local
# endpoint. An explicit $iface overrides the default-route lookup.
sub external_ipv4 {
    my ($iface) = @_;
    unless (defined $iface && length $iface) {
        for my $line (`ip -4 route show default 2>/dev/null`) {
            if ($line =~ /\bdev\s+(\S+)/) { $iface = $1; last }
        }
    }
    return (undef, undef) unless defined $iface && length $iface;
    for my $line (`ip -br -4 addr show dev $iface 2>/dev/null`) {
        my (undef, undef, @addrs) = split ' ', $line;
        for my $a (@addrs) {
            (my $ip = $a) =~ s|/.*||;
            return ($iface, $ip) if $ip =~ /^\d+\.\d+\.\d+\.\d+$/;
        }
    }
    return ($iface, undef);
}

# tunnel_addr($prefix_cidr, $suffix) — this end's address: the /64 + host suffix.
#   ("2001:470:1f1c:d10::/64", "2") -> "2001:470:1f1c:d10::2"
sub tunnel_addr {
    my ($prefix_cidr, $suffix) = @_;
    $suffix = '2' unless defined $suffix && length $suffix;
    my ($net) = $prefix_cidr =~ m{^(.+?)/} ? ($1) : ($prefix_cidr);
    $net =~ s/::$//;                          # "2001:470:1f1c:d10"
    my $addr = "$net\::$suffix";              # "2001:470:1f1c:d10::2"
    my $p = inet_pton(AF_INET6, $addr) or return $addr;
    return inet_ntop(AF_INET6, $p);
}

# up(%opts) — idempotently bring the 6in4 tunnel up. Returns ($local_v6, undef)
# or (undef, $error). opts: name, server (HE remote v4, required), prefix (HE
# /64 CIDR, required), local_v4 (auto if omitted), local_suffix (default '2'),
# forwarding (default on), ext_if, log coderef, run coderef (injectable).
sub up {
    my (%o) = @_;
    my $name   = $o{name}   || 'he-ipv6';
    my $server = $o{server} or return (undef, 'no server (HE remote IPv4)');
    my $prefix = $o{prefix} or return (undef, 'no prefix (HE /64)');
    my $log = $o{log} || sub {};
    my $run = $o{run} || sub { system(@_) == 0 };
    my $plen = ($prefix =~ m{/(\d+)}) ? $1 : 64;
    my $fwd  = (defined $o{forwarding}
                && lc("$o{forwarding}") =~ /^(0|off|no|false)$/) ? 0 : 1;

    my $local_v4 = $o{local_v4};
    unless (defined $local_v4 && length $local_v4) {
        (undef, $local_v4) = external_ipv4($o{ext_if});
    }
    return (undef, 'no local IPv4 (external endpoint down?)')
        unless defined $local_v4 && length $local_v4;
    my $local_v6 = tunnel_addr($prefix, $o{local_suffix});

    $run->('modprobe', 'sit');
    unless (`ip -o link show $name 2>/dev/null`) {
        $run->('ip', 'tunnel', 'add', $name, 'mode', 'sit',
               'remote', $server, 'local', $local_v4, 'ttl', '255')
            or return (undef, "ip tunnel add $name failed");
        $log->("he_net: created $name 6in4 (remote=$server local=$local_v4)");
    }
    $run->('ip', 'link', 'set', $name, 'up');
    # Enable IPv6 on the tunnel iface — a v6-disabled interface rejects
    # `ip -6 addr add` with EPERM even as root. Write /proc directly.
    my $dis = "/proc/sys/net/ipv6/conf/$name/disable_ipv6";
    if (-w $dis && open(my $dfh, '>', $dis)) { print $dfh "0\n"; close $dfh; }
    my $have = `ip -6 -o addr show dev $name 2>/dev/null`;
    if (index($have, $local_v6) < 0) {
        $run->('ip', 'addr', 'add', "$local_v6/$plen", 'dev', $name)
            or return (undef, "ip addr add $local_v6/$plen dev $name failed "
                            . "(RTNETLINK denied? daemon needs CAP_NET_ADMIN)");
        $log->("he_net: $name addr $local_v6/$plen");
    }
    $run->('ip', 'route', 'replace', '::/0', 'dev', $name)    # default v6 via tunnel
        or return (undef, "ip route replace ::/0 dev $name failed (no CAP_NET_ADMIN?)");
    $run->('sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1') if $fwd;
    $log->("he_net: $name up — local6=$local_v6 via $server"
         . ($fwd ? " (forwarding on)" : ""));
    return ($local_v6, undef);
}

# down(%opts) — tear the tunnel down (idempotent). opts: name, log, run.
sub down {
    my (%o) = @_;
    my $name = $o{name} || 'he-ipv6';
    my $run = $o{run} || sub { system(@_) == 0 };
    if (`ip -o link show $name 2>/dev/null`) {
        $run->('ip', 'tunnel', 'del', $name);
        ($o{log} || sub {})->("he_net: $name down");
    }
    return 1;
}

1;
