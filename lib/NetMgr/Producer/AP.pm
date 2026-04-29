package NetMgr::Producer::AP;
# Polls a DD-WRT access point via SSH, parses output, returns a list of
# OBSERVE-shaped hashrefs. The caller decides whether to send them to the
# manager socket or print them.

use strict;
use warnings;
use Carp qw(croak);

# Single shell script run per AP — one round trip per poll.
my $REMOTE_SCRIPT = <<'SH';
echo ===META===
nvram get router_name
nvram get DD_BOARD 2>/dev/null
nvram get lan_ipaddr 2>/dev/null
nvram get model 2>/dev/null
echo ===SSIDS===
nvram show 2>/dev/null | grep -E '^wl[0-9]+(\.[0-9]+)?_ssid='
echo ===INTERFACES===
ifconfig 2>/dev/null
echo ===ASSOC===
for i in eth0 eth1 eth2 ath0 ath1 ath2 wl0 wl1 wl0.1 wl0.2 wl0.3 wl1.1 wl1.2 wl1.3; do
  out=$(wl -i $i assoclist 2>/dev/null)
  if [ -n "$out" ]; then
    echo "IFACE $i"
    echo "$out"
    # Per-iface SSID — net-roam --list shows the SSID the client is on.
    s=$(wl -i $i ssid 2>/dev/null | sed -n 's/.*SSID: "\(.*\)".*/\1/p')
    [ -n "$s" ] && echo "SSID $i $s"
    # Per-client RSSI: lets net-roam find phones/tablets at the cell edge
    for cmac in $(echo "$out" | awk '{print $2}'); do
      r=$(wl -i $i rssi $cmac 2>/dev/null)
      [ -n "$r" ] && echo "RSSI $i $cmac $r"
    done
  fi
done
echo ===ARP===
cat /proc/net/arp 2>/dev/null
echo ===LEASES===
cat /tmp/dnsmasq.leases 2>/dev/null
echo ===END===
SH

sub poll_ap {
    my (%args) = @_;
    my $ip = $args{ip} or croak "ip required";
    my $ssh_user    = $args{ssh_user}    // 'root';
    my $ssh_timeout = $args{ssh_timeout} // 10;

    my @cmd = (
        'ssh',
        '-o', 'BatchMode=yes',
        '-o', "ConnectTimeout=$ssh_timeout",
        '-o', 'StrictHostKeyChecking=accept-new',
        '-n',
        "$ssh_user\@$ip",
        $REMOTE_SCRIPT,
    );

    my $pid = open(my $fh, '-|');
    croak "fork: $!" unless defined $pid;
    if ($pid == 0) {
        open STDERR, '>', '/dev/null';
        exec @cmd;
        exit 127;
    }
    my @lines = <$fh>;
    close $fh;
    my $exit = $? >> 8;

    if (!@lines || $exit != 0 && $exit != 255) {
        return { ok => 0, ip => $ip, exit => $exit, error => 'ssh failed' };
    }

    return parse_remote(\@lines, $ip);
}

# Parse the remote script's output into a structured result hash.
# Returns {
#   ok => 1, ip => $ip,
#   ap => { router_name, board, model, lan_ipaddr },
#   ssids => { 'wl0' => 'scorpius', 'wl0.1' => 'spica', ... },
#   interfaces => [ { name, mac } ... ],
#   associations => [ { iface, client_mac } ... ],
#   arp => [ { ip, mac, dev } ... ],
#   leases => [ { expires, mac, ip, hostname, client_id } ... ],
# }
sub parse_remote {
    my ($lines, $ip) = @_;
    my $section = '';
    my %meta;
    my $meta_idx = 0;
    my @meta_keys = qw(router_name board lan_ipaddr model);
    my %ssids;
    my @interfaces;
    my $cur_iface;
    my @assoc;
    my $assoc_iface;
    my %ssid_by_iface;     # iface (eth1, wl0.1, ...) → live SSID name
    my @arp;
    my @leases;

    for my $raw (@$lines) {
        my $line = $raw;
        $line =~ s/[\r\n]+\z//;
        # Skip the DD-WRT SSH banner lines that appear at the top of output
        next if $line =~ /^DD-WRT/ || $line =~ /^Release:/ || $line =~ /^Board:/;
        if ($line =~ /^===([A-Z]+)===$/) {
            $section = $1; $meta_idx = 0; $cur_iface = undef; $assoc_iface = undef;
            next;
        }

        if ($section eq 'META') {
            my $k = $meta_keys[$meta_idx++] // next;
            $meta{$k} = $line if length $line;
        }
        elsif ($section eq 'SSIDS') {
            if ($line =~ /^(wl[0-9]+(?:\.[0-9]+)?)_ssid=(.*)$/) {
                $ssids{$1} = $2 if length $2;
            }
        }
        elsif ($section eq 'INTERFACES') {
            if ($line =~ /^(\S+)\s+Link encap:\S+\s+HWaddr\s+(\S+)/) {
                push @interfaces, { name => $1, mac => lc $2 };
            }
            elsif ($line =~ /^(\S+):\s+flags=/) {
                $cur_iface = $1;
            }
            elsif ($line =~ /^\s+ether\s+(\S+)/ && $cur_iface) {
                push @interfaces, { name => $cur_iface, mac => lc $1 };
                $cur_iface = undef;
            }
        }
        elsif ($section eq 'ASSOC') {
            if ($line =~ /^IFACE\s+(\S+)/) {
                $assoc_iface = $1;
            }
            elsif ($line =~ /^SSID\s+(\S+)\s+(.+)/) {
                $ssid_by_iface{$1} = $2;
            }
            elsif ($line =~ /^assoclist\s+([0-9A-Fa-f:]{17})/ && $assoc_iface) {
                push @assoc, { iface => $assoc_iface, client_mac => lc $1 };
            }
            elsif ($line =~ /^RSSI\s+(\S+)\s+([0-9A-Fa-f:]{17})\s+(-?\d+)/) {
                # Last write wins per (iface, mac); attach to the matching
                # association entry below in to_observations().
                my ($if, $cmac, $rssi) = ($1, lc $2, $3 + 0);
                for my $a (@assoc) {
                    next unless $a->{iface} eq $if
                             && $a->{client_mac} eq $cmac;
                    $a->{signal} = $rssi;
                    last;
                }
            }
        }
        elsif ($section eq 'ARP') {
            # IP address       HW type     Flags       HW address            Mask     Device
            next if $line =~ /^IP address/;
            if ($line =~ /^(\S+)\s+\S+\s+\S+\s+([0-9a-fA-F:]{17})\s+\S+\s+(\S+)/) {
                next if $2 eq '00:00:00:00:00:00';
                push @arp, { ip => $1, mac => lc $2, dev => $3 };
            }
        }
        elsif ($section eq 'LEASES') {
            # 1777246586 9c:b6:d0:3f:45:cb 192.168.15.81 AMF-Laptop 01:9c:b6:d0:3f:45:cb 9
            if ($line =~ /^(\d+)\s+([0-9a-fA-F:]{17})\s+(\S+)\s+(\S+)/) {
                my ($exp,$mac,$lip,$host) = ($1,$2,$3,$4);
                push @leases, {
                    expires  => $exp+0,
                    mac      => lc $mac,
                    ip       => $lip,
                    hostname => ($host eq '*') ? undef : $host,
                };
            }
        }
    }

    # Attach the live SSID (from `wl ssid`) to each association entry,
    # keyed by iface. Used by net-roam --list to show which network the
    # client is actually on.
    for my $a (@assoc) {
        my $s = $ssid_by_iface{ $a->{iface} };
        $a->{ssid} = $s if defined $s && length $s;
    }

    return {
        ok           => 1,
        ip           => $ip,
        ap           => \%meta,
        ssids        => \%ssids,
        interfaces   => \@interfaces,
        associations => \@assoc,
        arp          => \@arp,
        leases       => \@leases,
    };
}

# Convert a parsed result into a list of OBSERVE-shaped hashrefs that the
# caller can hand to NetMgr::Protocol::format_kv as OBSERVE lines.
# Each returned hashref carries a leading 'via' tag identifying source.
sub to_observations {
    my ($r) = @_;
    return () unless $r && $r->{ok};
    my @obs;
    my $ap_ip   = $r->{ip};
    my $ap_name = $r->{ap}{router_name};
    my $via     = "ap:$ap_name";

    # AP's own identifying MAC: br0 carries the LAN IP, so its HWaddr is
    # what other producers (nmap, arp) see for this AP on the network.
    my ($br0) = grep { $_->{name} eq 'br0' } @{ $r->{interfaces} };
    my $ap_mac = $br0 ? $br0->{mac} : undef;

    push @obs, {
        kind   => 'ap_self',
        via    => $via,
        mac    => $ap_mac,
        ip     => $ap_ip,
        name   => $ap_name,
        board  => $r->{ap}{board},
        model  => $r->{ap}{model},
        ssid   => join(',', map { $r->{ssids}{$_} } sort keys %{ $r->{ssids} }),
        source => "$ap_ip:ssh",
    };

    # Associations: each client MAC seen by this AP
    for my $a (@{ $r->{associations} }) {
        push @obs, {
            kind       => 'association',
            via        => $via,
            ap_ip      => $ap_ip,
            iface      => $a->{iface},
            client_mac => $a->{client_mac},
            (defined $a->{signal} ? (signal => $a->{signal}) : ()),
            (defined $a->{ssid}   ? (ssid   => $a->{ssid})   : ()),
        };
    }

    # ARP entries from the AP — MAC↔IP for everything it sees on br0
    for my $a (@{ $r->{arp} }) {
        push @obs, {
            kind   => 'arp',
            via    => $via,
            mac    => $a->{mac},
            ip     => $a->{ip},
            dev    => $a->{dev},
            source => "$ap_ip:arp",
        };
    }

    # DHCP leases — only present when this AP is the DHCP server.
    # An entry here means the AP's dnsmasq handed out the lease (whether
    # static reservation or random) — we tag it as :DHCP and let
    # higher-authority sources (dhcp.master / dhcp.extra) override.
    for my $l (@{ $r->{leases} }) {
        push @obs, {
            kind     => 'lease',
            via      => $via,
            mac      => $l->{mac},
            ip       => $l->{ip},
            hostname => $l->{hostname},
            expires  => $l->{expires},
            source   => "$ap_ip:DHCP",
        };
    }

    return @obs;
}

1;
