package NetMgr::Producer::Scan;
# nmap / fping / ip-neigh based discovery. Returns lists of OBSERVE-shaped
# hashrefs. The CLI (bin/net-discover) decides what to do with them
# (push to manager or print).

use strict;
use warnings;
use Carp qw(croak);
use NetMgr::Vendor qw(shorten);

# Default port list — same shape as the legacy scan-network's set.
our @DEFAULT_PORTS = qw(22 23 25 53 80 443 515 554 2222 3389
                        5001 5900-5910 6000-6010 8899 9999 12345);

# Walk UP IPv4 LAN-side interfaces (eth*, en*, wl*) and return list of
# { iface, cidr, my_ip } for any 192.168.x.0/24 they sit on. Skips lo,
# bridges, virtual interfaces (vmnet*, docker*, virbr*, etc.) — those
# get caught by the `^(eth|en|wl)` prefix gate.
sub detect_networks {
    open my $fh, '-|', 'ip', '-o', '-4', 'addr', 'show'
        or croak "ip: $!";
    my @nets;
    while (my $line = <$fh>) {
        next unless $line =~ /^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)\/(\d+)/;
        my ($iface, $ip, $bits) = ($1, $2, $3);
        next unless $iface =~ /^(eth|en|wl)/;
        next unless $ip    =~ /^192\.168\./;
        my @oct = split /\./, $ip;
        my $cidr = "$oct[0].$oct[1].$oct[2].0/24";
        push @nets, { iface => $iface, cidr => $cidr, my_ip => $ip };
    }
    close $fh;
    return @nets;
}

# Read /proc/net/arp + ip neigh into a {ip => mac} map for v4.
sub neighbours {
    my %seen;
    open my $n, '-|', 'ip', '-4', 'neigh', 'show' or return %seen;
    while (my $line = <$n>) {
        next unless $line =~ /^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+(\S+)/;
        my ($ip, $mac) = ($1, lc $2);
        next if $mac eq '00:00:00:00:00:00';
        $seen{$ip} = $mac;
    }
    close $n;
    return %seen;
}

# Run nmap once over a single network. Returns ($obs_arrayref, $error_str).
# Each observation is a hashref with kind=host or kind=port and other fields.
sub discover_network {
    my (%args) = @_;
    my $iface  = $args{iface}  or croak "iface required";
    my $cidr   = $args{cidr}   or croak "cidr required";
    my $ports  = $args{ports}  // join(',', @DEFAULT_PORTS);
    my $timeout= $args{host_timeout} // 20;

    my @cmd = ('nmap', "--host-timeout=$timeout", '-n', '-P0',
               '-p', $ports, '--open');
    push @cmd, '-e', $iface unless $iface eq 'auto';
    push @cmd, $cidr;
    open my $fh, '-|', @cmd or return ([], "nmap: $!");

    my %hosts;       # ip → { mac, vendor, ports => [...] }
    my $cur_ip;
    while (my $line = <$fh>) {
        chomp $line;
        if ($line =~ /^Nmap scan report for (\d+\.\d+\.\d+\.\d+)/) {
            $cur_ip = $1;
            $hosts{$cur_ip} ||= { ports => [] };
        }
        elsif ($cur_ip && $line =~ /^MAC Address:\s+(\S+)\s+\((.*)\)/) {
            $hosts{$cur_ip}{mac}    = lc $1;
            $hosts{$cur_ip}{vendor} = $2 eq 'Unknown' ? undef : shorten($2);
        }
        elsif ($cur_ip && $line =~ m{^(\d+)/(tcp|udp)\s+open\s*(.*)}) {
            push @{ $hosts{$cur_ip}{ports} },
                { port => $1+0, proto => $2,
                  service => (length $3 ? $3 : undef) };
        }
    }
    close $fh;

    # Backfill missing MACs from ip-neigh (e.g. for our own subnet hosts
    # nmap may not capture if they responded only via TCP).
    my %nb = neighbours();
    for my $ip (keys %hosts) {
        $hosts{$ip}{mac} //= $nb{$ip};
    }

    my @obs;
    for my $ip (sort _ip_sort keys %hosts) {
        my $h = $hosts{$ip};
        next unless $h->{mac};   # without a MAC we have nothing to upsert
        push @obs, {
            kind   => 'host',
            mac    => $h->{mac},
            ip     => $ip,
            family => 'v4',
            vendor => $h->{vendor},
            kind_  => 'ethernet',   # interface kind (renamed below)
        };
        for my $p (@{ $h->{ports} }) {
            push @obs, {
                kind    => 'port',
                mac     => $h->{mac},
                port    => $p->{port},
                proto   => $p->{proto},
                service => $p->{service},
            };
        }
    }
    return (\@obs, undef);
}

# Helper: numeric sort on dotted-quad IPv4
sub _ip_sort {
    my @a = split /\./, $a;
    my @b = split /\./, $b;
    return $a[0]<=>$b[0] || $a[1]<=>$b[1] || $a[2]<=>$b[2] || $a[3]<=>$b[3];
}

# Quick presence check via fping. Given a list of IPs, returns
# { alive => [...], dead => [...] }.
sub fping_presence {
    my (@ips) = @_;
    return { alive => [], dead => [] } unless @ips;
    my %res;
    open my $fh, '-|', 'fping', '-q', '-r', '1', '-a', @ips
        or return { alive => [], dead => [], error => "fping: $!" };
    my %alive = map { chomp; ($_, 1) } <$fh>;
    close $fh;
    return {
        alive => [ grep {  $alive{$_} } @ips ],
        dead  => [ grep { !$alive{$_} } @ips ],
    };
}

# Presence + per-host RTT. Returns
#   { alive => { ip => $rtt_ms }, dead => [...] }
# Uses `fping -C 1 -q` which writes one summary line per IP:
#   192.168.15.31 : 0.34       (alive, 0.34 ms)
#   192.168.15.99 : -          (unreachable)
# `-C 1` does a single ping per host; for multiple samples bump the
# arg, but the manager wants per-call snapshots so 1 is fine. The
# summary goes to stderr; merge it via a shelled-out invocation.
sub fping_rtt {
    my (@ips) = @_;
    return { alive => {}, dead => [] } unless @ips;
    my $cmd = 'fping -C 1 -q '
            . join(' ', map { quotemeta } @ips)
            . ' 2>&1';
    open my $fh, '-|', $cmd
        or return { alive => {}, dead => [], error => "fping: $!" };
    my %alive;
    while (my $line = <$fh>) {
        chomp $line;
        if ($line =~ /^(\S+)\s*:\s*([\d.]+)\s*$/) {
            $alive{$1} = $2 + 0;
        }
    }
    close $fh;
    my @dead = grep { !exists $alive{$_} } @ips;
    return { alive => \%alive, dead => \@dead };
}

1;
