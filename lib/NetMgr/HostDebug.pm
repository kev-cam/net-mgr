package NetMgr::HostDebug;
# Pure-Perl host-side network state collector.
#
# Used by:
#   - bin/net-diag (default no-arg mode)        — runs on the local host
#   - lib/NetMgr/Manager.pm (POLL host-debug)   — runs on the daemon host
#
# Returns a single multi-line plaintext report. The shape is meant to
# be readable by humans first, parseable by sed/awk second. Sections
# are headed by `==[ NAME ]==`; within a section, lines are
# `key: value` or free-form depending on the topic.
#
# Everything is best-effort: each helper traps errors and falls back
# to "(unavailable: REASON)" so the report always finishes.

use strict;
use warnings;
use Exporter 'import';
use POSIX ();

our @EXPORT_OK = qw(collect format_report);

sub collect {
    my %r;
    $r{hostname}   = _read_hostname();
    $r{uname}      = _capture('uname', '-a');
    $r{interfaces} = _interfaces();
    $r{routes_v4}  = _capture('ip', '-4', 'route', 'show');
    $r{routes_v6}  = _capture('ip', '-6', 'route', 'show');
    $r{dns}        = _dns();
    $r{listeners}  = _listeners();
    $r{services}   = _services();
    $r{dhcp}       = _dhcp();
    $r{router}     = _router();
    return \%r;
}

# Convenience: collect + format in one shot. This is what the daemon's
# POLL host-debug handler returns (base64-encoded).
sub format_report {
    my ($r) = @_;
    $r //= collect();
    my $now = POSIX::strftime('%Y-%m-%d %H:%M:%S %Z', localtime);
    my @out;
    push @out, "==[ host-debug @ $r->{hostname}  $now ]==";
    push @out, "  $r->{uname}" if $r->{uname};
    push @out, '';

    # Interfaces
    push @out, "==[ INTERFACES ]==";
    if (ref $r->{interfaces} eq 'ARRAY' && @{ $r->{interfaces} }) {
        for my $i (@{ $r->{interfaces} }) {
            my $tag = $i->{kind} // '?';
            push @out, sprintf("  %-12s  %-9s  %-17s  %s",
                $i->{name}, $tag, ($i->{mac} // '-'),
                join('/', @{ $i->{flags} || [] }) || '-');
            for my $a (@{ $i->{addrs} || [] }) {
                push @out, "      $a";
            }
            for my $extra (@{ $i->{extra} || [] }) {
                push @out, "      $extra";
            }
        }
    } else {
        push @out, "  (no interfaces parsed)";
    }
    push @out, '';

    # Routes
    push @out, "==[ ROUTES (v4) ]==";
    push @out, _indent($r->{routes_v4} // '');
    if ($r->{routes_v6} && $r->{routes_v6} =~ /\S/) {
        push @out, '';
        push @out, "==[ ROUTES (v6) ]==";
        push @out, _indent($r->{routes_v6});
    }
    push @out, '';

    # DNS
    push @out, "==[ DNS ]==";
    for my $line (@{ $r->{dns}{summary} || ['(no DNS info)'] }) {
        push @out, "  $line";
    }
    if ($r->{dns}{resolv_conf}) {
        push @out, "  --- /etc/resolv.conf ---";
        my $rc = $r->{dns}{resolv_conf};
        # strip comment-only and blank lines — boilerplate from
        # systemd-resolved's stub file is just noise here
        $rc = join("\n", grep { /\S/ && !/^\s*#/ } split /\n/, $rc);
        push @out, _indent($rc, 4);
    }
    if ($r->{dns}{resolvectl}) {
        push @out, "  --- resolvectl status ---";
        push @out, _indent($r->{dns}{resolvectl}, 4);
    }
    push @out, '';

    # DHCP
    push @out, "==[ DHCP ]==";
    if (@{ $r->{dhcp}{clients} || [] }) {
        push @out, "  active client processes:";
        push @out, "    $_" for @{ $r->{dhcp}{clients} };
    } else {
        push @out, "  no DHCP client processes detected";
    }
    if (@{ $r->{dhcp}{servers} || [] }) {
        push @out, "  active server processes:";
        push @out, "    $_" for @{ $r->{dhcp}{servers} };
    }
    if (@{ $r->{dhcp}{leases} || [] }) {
        push @out, "  leases:";
        push @out, sprintf("    %-8s  %-15s  %-15s  %s",
            "IFACE", "IP", "SERVER", "REMAINING");
        for my $L (@{ $r->{dhcp}{leases} }) {
            push @out, sprintf("    %-8s  %-15s  %-15s  %s",
                $L->{iface}  // '?',
                $L->{ip}     // '?',
                $L->{server} // '?',
                $L->{remaining} // '?');
        }
    }
    push @out, '';

    # Router-readiness
    push @out, "==[ ROUTER ]==";
    my $rt = $r->{router} || {};
    push @out, "  ip_forward (v4):    " . ($rt->{ip_forward}    // '?');
    push @out, "  ip_forward (v6):    " . ($rt->{ip_forward_v6} // '?');
    if (@{ $rt->{defaults} || [] }) {
        push @out, "  default routes:";
        push @out, "    $_" for @{ $rt->{defaults} };
    } else {
        push @out, "  default routes:     (none)";
    }
    if ($rt->{nat_postrouting}) {
        push @out, "  NAT POSTROUTING:    $rt->{nat_postrouting}";
    }
    if ($rt->{filter_forward}) {
        push @out, "  FILTER FORWARD:     $rt->{filter_forward}";
    }
    if (@{ $rt->{ssh_tunnels} || [] }) {
        push @out, "  ssh tunnels:";
        push @out, "    $_" for @{ $rt->{ssh_tunnels} };
    } else {
        push @out, "  ssh tunnels:        (none)";
    }
    push @out, '';

    # Listeners
    push @out, "==[ LISTENERS (relevant ports) ]==";
    if (@{ $r->{listeners} || [] }) {
        push @out, sprintf("  %-6s  %-25s  %s", "PROTO", "LOCAL", "PROCESS");
        for my $L (@{ $r->{listeners} }) {
            push @out, sprintf("  %-6s  %-25s  %s",
                $L->{proto}, $L->{local}, $L->{proc} // '?');
        }
    } else {
        push @out, "  (none / ss not available)";
    }
    push @out, '';

    # Services
    push @out, "==[ NETWORK SERVICES ]==";
    if (ref $r->{services} eq 'ARRAY' && @{ $r->{services} }) {
        push @out, sprintf("  %-25s  %-10s  %s", "UNIT", "ACTIVE", "ENABLED");
        for my $s (@{ $r->{services} }) {
            push @out, sprintf("  %-25s  %-10s  %s",
                $s->{name}, $s->{active}, $s->{enabled});
        }
    } else {
        push @out, "  (systemctl not available)";
    }

    return join("\n", @out) . "\n";
}

# -------------------------------------------------------------------
# Sources
# -------------------------------------------------------------------

sub _read_hostname {
    chomp(my $h = `hostname 2>/dev/null`);
    return $h || '?';
}

sub _capture {
    my (@cmd) = @_;
    my $pid = open my $fh, '-|';
    return "(fork failed: $!)" unless defined $pid;
    if ($pid == 0) {
        open STDERR, '>', '/dev/null';
        exec @cmd;
        exit 127;
    }
    my $out;
    {
        local $/;
        $out = <$fh> // '';
    }
    close $fh;
    $out =~ s/\s+\z//;
    return $out;
}

sub _interfaces {
    # `ip -d -j addr show` would give us JSON, but JSON is non-core
    # on older perls. Parse `ip -br link/addr` instead — both are
    # stable across iproute2 versions.
    my @out;
    my %seen;

    my $br_link = _capture('ip', '-br', 'link', 'show');
    my $br_addr = _capture('ip', '-br', 'addr', 'show');

    # parse `ip -br link show`:
    #   eth0  UP  aa:bb:cc:dd:ee:ff <BROADCAST,MULTICAST,UP,LOWER_UP>
    for my $line (split /\n/, $br_link) {
        my @f = split ' ', $line;
        next unless @f >= 2;
        my $name  = $f[0];
        my $state = $f[1];
        my $mac   = (@f >= 3 && $f[2] =~ /^[0-9a-f:]{17}$/i) ? lc $f[2] : undef;
        my @flags;
        if (@f >= 4 && $f[-1] =~ /^<(.+)>$/) {
            @flags = split /,/, $1;
        }
        push @flags, "STATE=$state";

        my $kind = _classify_iface($name, \@flags);

        $seen{$name} = {
            name => $name, kind => $kind, mac => $mac,
            flags => \@flags, addrs => [], extra => [],
        };
        push @out, $seen{$name};
    }

    # parse `ip -br addr show`:
    #   eth0  UP  192.168.15.170/24  fe80::xxxx/64
    for my $line (split /\n/, $br_addr) {
        my @f = split ' ', $line;
        next unless @f >= 1;
        my $name = $f[0];
        my $iface = $seen{$name} or next;
        for my $a (@f[2..$#f]) {
            push @{ $iface->{addrs} }, $a if $a =~ m{/};
        }
    }

    # Bridge / VLAN / wifi extras (best effort).
    for my $iface (@out) {
        my $n = $iface->{name};
        if ($iface->{kind} eq 'bridge') {
            my $members = _bridge_members($n);
            push @{ $iface->{extra} }, "bridge members: $members" if $members;
        } elsif ($iface->{kind} eq 'wifi') {
            my $info = _wifi_info($n);
            push @{ $iface->{extra} }, $info if $info;
        }
    }

    return \@out;
}

sub _classify_iface {
    my ($name, $flags) = @_;
    return 'loopback' if $name eq 'lo';
    return 'bridge'   if -d "/sys/class/net/$name/bridge";
    return 'vlan'     if -e "/proc/net/vlan/$name";
    if (-d "/sys/class/net/$name/wireless"
     || -e "/sys/class/net/$name/phy80211") {
        return 'wifi';
    }
    return 'tunnel'   if $name =~ /^(?:tun|tap|wg)\d/;
    return 'virtual'  if $name =~ /^(?:veth|docker|br-|virbr)/;
    return 'ethernet';
}

sub _bridge_members {
    my ($br) = @_;
    my $dir = "/sys/class/net/$br/brif";
    opendir my $dh, $dir or return undef;
    my @m = sort grep { !/^\./ } readdir $dh;
    closedir $dh;
    return @m ? join(' ', @m) : '(empty)';
}

sub _wifi_info {
    my ($iface) = @_;
    # iw is the modern tool; iwconfig (wireless-tools) is the older.
    my $out = _capture('iw', 'dev', $iface, 'link');
    return undef unless $out && $out !~ /^\(/;
    my @bits;
    push @bits, "SSID=$1"      if $out =~ /SSID:\s*(\S+)/;
    push @bits, "signal=$1dBm" if $out =~ /signal:\s*(-?\d+)/;
    push @bits, "freq=$1"      if $out =~ /freq:\s*(\d+)/;
    return @bits ? join(' ', "wifi:", @bits) : undef;
}

sub _dns {
    my %r;
    my @summary;

    if (open my $fh, '<', '/etc/resolv.conf') {
        local $/;
        $r{resolv_conf} = <$fh>;
        close $fh;
        for my $line (split /\n/, $r{resolv_conf} // '') {
            push @summary, $line if $line =~ /^\s*(nameserver|search|domain)\b/;
        }
    } else {
        push @summary, "/etc/resolv.conf: (unreadable: $!)";
    }

    # systemd-resolved if present + active.
    my $rc = _capture('resolvectl', 'status');
    if ($rc && $rc !~ /command not found|^\(/) {
        $r{resolvectl} = $rc;
    }

    push @summary, "(no nameserver lines in resolv.conf)" unless @summary;
    $r{summary} = \@summary;
    return \%r;
}

sub _listeners {
    # ss is on virtually every modern Linux; netstat is the fallback.
    my $out = _capture('ss', '-Hlnp');
    if (!$out || $out =~ /^\(/) {
        $out = _capture('netstat', '-lnp');
    }
    return [] unless $out;

    my @r;
    my %wanted = (
        53 => 'DNS', 67 => 'DHCPserver', 68 => 'DHCPclient',
        69 => 'TFTP', 123 => 'NTP', 137 => 'NetBIOS',
        138 => 'NetBIOS', 139 => 'NetBIOS', 161 => 'SNMP',
        445 => 'SMB', 547 => 'DHCPv6', 631 => 'IPP',
        2049 => 'NFS', 5353 => 'mDNS', 5355 => 'LLMNR',
        7531 => 'net-mgr', 7532 => 'net-mgr-dnsmasq-event',
    );
    for my $line (split /\n/, $out) {
        my @f = split ' ', $line;
        next unless @f >= 5;
        my ($proto, $local) = ($f[0], $f[4]);
        next unless $local =~ /:(\d+)$/;
        my $port = $1 + 0;
        next unless $wanted{$port};
        my $proc;
        if ($line =~ /users:\(\("([^"]+)"/) { $proc = $1 }
        push @r, {
            proto => $proto, local => $local,
            proc  => $proc ? "$proc ($wanted{$port})" : "($wanted{$port})",
        };
    }
    return [ sort { _port_of($a->{local}) <=> _port_of($b->{local}) } @r ];
}

sub _port_of {
    my ($addr) = @_;
    return $addr =~ /:(\d+)$/ ? $1 + 0 : 0;
}

sub _services {
    return [] unless _have('systemctl');
    my @units = qw(
        net-mgr.service net-dns.service net-mgr-relay.service
        dnsmasq.service systemd-resolved.service systemd-networkd.service
        NetworkManager.service named.service unbound.service
        isc-dhcp-server.service kea-dhcp4-server.service
        avahi-daemon.service
    );
    my @r;
    for my $u (@units) {
        my $active  = _capture('systemctl', 'is-active', $u);
        my $enabled = _capture('systemctl', 'is-enabled', $u);
        # 'systemctl is-enabled' returns 'static' / 'masked' / etc.
        # 'is-active' returns 'inactive' for not-installed too. Skip
        # truly-unknown units to keep noise down.
        next if $active eq 'inactive' && ($enabled eq 'disabled'
                                       || $enabled =~ /not-found|No such/);
        next if $enabled =~ /not-found|No such/;
        push @r, { name => $u, active => $active, enabled => $enabled };
    }
    return \@r;
}

sub _dhcp {
    my %r;
    # Client processes (dhclient, dhcpcd, systemd-networkd, NetworkManager).
    my @procs;
    if (open my $fh, '-|', 'ps', '-eo', 'pid,comm,args') {
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /\b(dhclient|dhcpcd|udhcpc)\b/
                     || $line =~ /\bdnsmasq\b/
                     || $line =~ /\bnetworkd\b/
                     || $line =~ /\bNetworkManager\b/;
            push @procs, $line;
        }
        close $fh;
    }
    # Split into clients vs servers heuristically.
    my (@cl, @sv);
    for my $p (@procs) {
        if ($p =~ /\b(dhclient|dhcpcd|udhcpc)\b/)             { push @cl, $p }
        elsif ($p =~ /\b(dnsmasq|isc-dhcp-server|kea-dhcp4)\b/) { push @sv, $p }
    }
    $r{clients} = \@cl;
    $r{servers} = \@sv;

    # Parsed lease summaries — one row per interface, latest lease wins.
    $r{leases} = _parse_leases();
    return \%r;
}

# Returns an arrayref of { iface, ip, server, remaining } hashes
# from any lease file we recognise. Currently handles ISC dhclient
# format (the most common Linux). Files unread (perms) or unparseable
# are skipped silently. If multiple lease blocks reference the same
# interface, the last one wins (matches dhclient's own "latest" rule).
sub _parse_leases {
    my @rows;
    my %by_iface;
    for my $glob ('/var/lib/dhcp/dhclient*.leases',
                  '/var/lib/dhclient/dhclient*.lease*') {
        for my $path (glob $glob) {
            next unless -r $path;
            open my $fh, '<', $path or next;
            my $lease; my @blocks;
            while (my $line = <$fh>) {
                $line =~ s/[\r\n]+\z//;
                if ($line =~ /^\s*lease\s*\{/) { $lease = {} }
                elsif ($line =~ /^\s*\}/)        { push @blocks, $lease if $lease; $lease = undef }
                elsif ($lease) {
                    if    ($line =~ /interface\s+"([^"]+)"/)               { $lease->{iface}  = $1 }
                    elsif ($line =~ /fixed-address\s+(\S+?);/)              { $lease->{ip}     = $1 }
                    elsif ($line =~ /dhcp-server-identifier\s+(\S+?);/)     { $lease->{server} = $1 }
                    elsif ($line =~ /expire\s+\d+\s+(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})/) {
                        $lease->{expire_str} = $1;
                    }
                }
            }
            close $fh;
            for my $b (@blocks) {
                next unless $b->{iface};
                $by_iface{ $b->{iface} } = $b;   # last lease wins
            }
        }
    }
    for my $iface (sort keys %by_iface) {
        my $b = $by_iface{$iface};
        push @rows, {
            iface     => $iface,
            ip        => $b->{ip},
            server    => $b->{server},
            remaining => _format_remaining($b->{expire_str}),
        };
    }
    return \@rows;
}

# dhclient writes 'expire W YYYY/MM/DD HH:MM:SS' in UTC.
sub _format_remaining {
    my ($s) = @_;
    return undef unless defined $s
        && $s =~ m{^(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$};
    require Time::Local;
    my $expire = Time::Local::timegm($6,$5,$4,$3,$2-1,$1-1900);
    my $secs = $expire - time();
    return 'expired' if $secs <= 0;
    if    ($secs < 60)        { return "${secs}s" }
    elsif ($secs < 3600)      { return sprintf "%dm%02ds", $secs/60, $secs%60 }
    elsif ($secs < 86400)     { return sprintf "%dh%02dm", $secs/3600, ($secs%3600)/60 }
    else                       { return sprintf "%dd%02dh", $secs/86400, ($secs%86400)/3600 }
}

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

sub _router {
    my %r;
    $r{ip_forward}    = _read_first('/proc/sys/net/ipv4/ip_forward');
    $r{ip_forward_v6} = _read_first('/proc/sys/net/ipv6/conf/all/forwarding');

    # Default routes summarised one per line (iface + via).
    my @defaults;
    for my $line (split /\n/, _capture('ip', '-4', 'route', 'show', 'default')) {
        # default via 192.168.15.252 dev eth0 proto dhcp metric 20101
        my ($via)  = $line =~ /\bvia\s+(\S+)/;
        my ($dev)  = $line =~ /\bdev\s+(\S+)/;
        my ($metric)=$line =~ /\bmetric\s+(\S+)/;
        next unless $via && $dev;
        my $s = "via $via dev $dev";
        $s .= " metric $metric" if defined $metric;
        push @defaults, $s;
    }
    $r{defaults} = \@defaults;

    # NAT POSTROUTING summary (counts of MASQUERADE / SNAT rules and
    # any non-default chain targets). iptables-save doesn't need root
    # on most distros if we only want -L counters; we use -nvL on the
    # nat table because it's the cleanest.
    if (_have('iptables')) {
        my $nat = _capture('iptables', '-t', 'nat', '-S', 'POSTROUTING');
        my @lines = grep { /^-A/ } split /\n/, $nat;
        my $masq  = grep { /-j MASQUERADE/ } @lines;
        my $snat  = grep { /-j SNAT/ }       @lines;
        my $other = scalar(@lines) - $masq - $snat;
        $r{nat_postrouting} = sprintf "%d rules (MASQUERADE=%d SNAT=%d other=%d)",
            scalar(@lines), $masq, $snat, $other;
        # Also note the FORWARD policy + rule count — a router needs
        # to be ACCEPTing or have explicit allow rules.
        my $fwd = _capture('iptables', '-S', 'FORWARD');
        my @fl  = split /\n/, $fwd;
        my ($pol) = $fwd =~ /^-P FORWARD (\S+)/m;
        my $fcount = grep { /^-A/ } @fl;
        $r{filter_forward} = sprintf "policy=%s rules=%d",
            ($pol // '?'), $fcount;
    }

    # SSH tunnel processes — heuristic: ssh client invocations with
    # -N (no command) or -R/-L forwards. Tunnel-back-to-ISP processes
    # are the canonical "is the cellular link alive" signal on
    # one-way uplinks.
    my @tun;
    if (open my $fh, '-|', 'ps', '-eo', 'pid,etime,args') {
        my $hdr = <$fh>;    # discard header
        while (my $line = <$fh>) {
            chomp $line;
            # drop leading pid + etime, look at args
            next unless $line =~ /^\s*\d+\s+\S+\s+(.*)$/;
            my $args = $1;
            # match ssh clients only (not sshd)
            next unless $args =~ /^(?:\S*\/)?ssh(?:\s|$)/;
            next unless $args =~ /\s-N\b/
                     || $args =~ /\s-[RL]\s/
                     || $args =~ /\sControlMaster=/i;
            push @tun, $line;
        }
        close $fh;
    }
    $r{ssh_tunnels} = \@tun;

    return \%r;
}

sub _read_first {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    my $line = <$fh>;
    close $fh;
    return undef unless defined $line;
    chomp $line;
    return $line;
}

sub _have {
    my ($cmd) = @_;
    for my $d (split /:/, $ENV{PATH} // '/usr/sbin:/sbin:/usr/bin:/bin') {
        return 1 if -x "$d/$cmd";
    }
    return 0;
}

sub _indent {
    my ($s, $n) = @_;
    $n //= 2;
    my $pad = ' ' x $n;
    return join("\n", map { "$pad$_" } split /\n/, $s);
}

1;
